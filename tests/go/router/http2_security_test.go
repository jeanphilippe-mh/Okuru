package router

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	u "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	"golang.org/x/net/http2"
)

// An in-memory duplex connection exercises real HTTP/2 streams without
// opening a listening socket or contacting an external service.
func newHTTP2Pipe(t *testing.T, handler http.Handler) *http2.ClientConn {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	finished := make(chan struct{})
	go func() {
		defer close(finished)
		(&http2.Server{MaxConcurrentStreams: 32}).ServeConn(serverConn, &http2.ServeConnOpts{Handler: handler})
	}()
	client, err := (&http2.Transport{}).NewClientConn(clientConn)
	if err != nil {
		_ = serverConn.Close()
		_ = clientConn.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = clientConn.Close()
		_ = serverConn.Close()
		select {
		case <-finished:
		case <-time.After(2 * time.Second):
			t.Error("HTTP/2 server did not stop")
		}
	})
	return client
}

func newLimitedHTTP2Router(idle time.Duration) *echo.Echo {
	e := echo.New()
	e.Use(requestLimits(idle, 10*time.Second, 10*time.Second))
	return e
}

func configureHTTP2UploadStorage(t *testing.T) {
	t.Helper()
	previous := u.FILEFOLDER
	u.FILEFOLDER = t.TempDir()
	t.Cleanup(func() { u.FILEFOLDER = previous })
	t.Setenv("OKURU_STORAGE_MIN_FREE_BYTES", "1")
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", "8589934592")
	t.Setenv("OKURU_STORAGE_MAX_ARCHIVES", "1000")
}

func TestHTTP2ProgressingUploadOutlivesIdleInterval(t *testing.T) {
	configureHTTP2UploadStorage(t)
	const idle = 800 * time.Millisecond
	e := newLimitedHTTP2Router(idle)
	e.POST("/file", func(c echo.Context) error {
		body, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return err
		}
		return c.String(http.StatusOK, string(body))
	})
	client := newHTTP2Pipe(t, e)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	writeDone := make(chan error, 1)
	go func() {
		for i := 0; i < 6; i++ {
			if _, err := io.WriteString(writer, "part"); err != nil {
				writeDone <- err
				return
			}
			time.Sleep(200 * time.Millisecond)
		}
		writeDone <- writer.Close()
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://unit.invalid/file", reader)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set(echo.HeaderContentType, "multipart/form-data; boundary=test")
	req.ContentLength = 24
	resp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK || string(body) != strings.Repeat("part", 6) {
		t.Fatalf("progressing HTTP/2 upload failed: proto=%s status=%d body=%q error=%v", resp.Proto, resp.StatusCode, body, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

func TestHTTP2StalledUploadDoesNotBlockAnotherStream(t *testing.T) {
	configureHTTP2UploadStorage(t)
	const idle = 350 * time.Millisecond
	e := newLimitedHTTP2Router(idle)
	started := make(chan struct{})
	readResult := make(chan error, 1)
	e.POST("/file", func(c echo.Context) error {
		one := make([]byte, 1)
		if _, err := io.ReadFull(c.Request().Body, one); err != nil {
			return err
		}
		close(started)
		_, err := io.Copy(io.Discard, c.Request().Body)
		readResult <- err
		if err != nil {
			return echo.NewHTTPError(http.StatusRequestTimeout)
		}
		return c.NoContent(http.StatusOK)
	})
	e.GET("/health", func(c echo.Context) error { return c.String(http.StatusOK, "ok") })
	client := newHTTP2Pipe(t, e)
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://unit.invalid/file", reader)
	req.Header.Set(echo.HeaderContentType, "multipart/form-data; boundary=test")
	req.ContentLength = 8
	result := make(chan error, 1)
	unexpectedSuccess := errors.New("stalled upload unexpectedly completed")
	go func() {
		resp, err := client.RoundTrip(req)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				err = unexpectedSuccess
			}
		}
		result <- err
	}()
	go func() { _, _ = writer.Write([]byte("x")) }()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("upload did not start")
	}
	fast, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://unit.invalid/health", nil)
	resp, err := client.RoundTrip(fast)
	if err != nil {
		t.Fatalf("unrelated HTTP/2 stream failed: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("unrelated stream: status=%d body=%q error=%v", resp.StatusCode, body, err)
	}
	select {
	case err := <-readResult:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("stalled read did not end with a deadline: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("stalled HTTP/2 read was not interrupted")
	}
	select {
	case err := <-result:
		if errors.Is(err, unexpectedSuccess) {
			t.Fatal(err)
		}
		if err != nil && ctx.Err() != nil {
			t.Fatalf("stalled upload outlived test deadline: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("stalled HTTP/2 upload was not stopped")
	}
}

func TestHTTP2SlowReaderReceivesCompleteDownload(t *testing.T) {
	const idle = 800 * time.Millisecond
	e := newLimitedHTTP2Router(idle)
	// Exceed the usual HTTP/2 receive window so a slow reader eventually
	// applies stream-level backpressure, as in an actual archive download.
	payload := bytes.Repeat([]byte("a"), 8<<20)
	e.GET("/file/download", func(c echo.Context) error {
		http.ServeContent(c.Response(), c.Request(), "archive.zip", time.Time{}, bytes.NewReader(payload))
		return nil
	})
	client := newHTTP2Pipe(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://unit.invalid/file/download", nil)
	resp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var received bytes.Buffer
	buf := make([]byte, 32<<10)
	started := time.Now()
	for {
		n, err := resp.Body.Read(buf)
		_, _ = received.Write(buf[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK || !bytes.Equal(received.Bytes(), payload) {
		t.Fatalf("slow reader received incomplete data: proto=%s status=%d bytes=%d", resp.Proto, resp.StatusCode, received.Len())
	}
	if time.Since(started) <= idle {
		t.Fatal("test did not exercise a transfer longer than the idle interval")
	}
}

func TestHTTP2StalledDownloadIsBounded(t *testing.T) {
	const idle = 350 * time.Millisecond
	e := newLimitedHTTP2Router(idle)
	writeResult := make(chan error, 1)
	e.GET("/file/stall", func(c echo.Context) error {
		chunk := bytes.Repeat([]byte("x"), 32<<10)
		for i := 0; i < 1024; i++ {
			if _, err := c.Response().Write(chunk); err != nil {
				writeResult <- err
				return nil
			}
		}
		writeResult <- nil
		return nil
	})
	e.GET("/health", func(c echo.Context) error { return c.String(http.StatusOK, "ok") })
	client := newHTTP2Pipe(t, e)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://unit.invalid/file/stall", nil)
	resp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected response: %s %d", resp.Proto, resp.StatusCode)
	}
	// Do not consume the response: HTTP/2 flow control eventually blocks the
	// writer, which must be released by its stream write deadline.
	started := time.Now()
	select {
	case err := <-writeResult:
		if err == nil {
			t.Fatal("download completed despite an unread response")
		}
		if time.Since(started) < idle/2 {
			t.Fatalf("download failed before exercising the idle deadline: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("stalled HTTP/2 download did not stop")
	}
	fast, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://unit.invalid/health", nil)
	other, err := client.RoundTrip(fast)
	if err != nil {
		t.Fatalf("a stalled response affected another stream: %v", err)
	}
	body, err := io.ReadAll(other.Body)
	_ = other.Body.Close()
	if err != nil || other.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("unrelated stream: status=%d body=%q error=%v", other.StatusCode, body, err)
	}
}
