package router

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

type multipartPipeListener struct {
	conn   net.Conn
	closed chan struct{}
}

func (l *multipartPipeListener) Accept() (net.Conn, error) {
	if l.conn != nil {
		c := l.conn
		l.conn = nil
		return c, nil
	}
	<-l.closed
	return nil, net.ErrClosed
}
func (l *multipartPipeListener) Close() error {
	select {
	case <-l.closed:
	default:
		close(l.closed)
	}
	return nil
}
func (l *multipartPipeListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func makeMultipartBody(t *testing.T, csrf string, size int) (*bytes.Buffer, string) {
	t.Helper()
	body := new(bytes.Buffer)
	w := multipart.NewWriter(body)
	p, err := w.CreateFormFile("files", "private.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(p, strings.Repeat("x", size)); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteField("password", "passphrase"); err != nil {
		t.Fatal(err)
	}
	if csrf != "" {
		if err := w.WriteField("_csrf", csrf); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return body, w.FormDataContentType()
}

func TestSecureMultipartPrecedesCSRFAndPreservesTokenVariants(t *testing.T) {
	old := utils.FILEFOLDER
	utils.FILEFOLDER = t.TempDir()
	t.Cleanup(func() { utils.FILEFOLDER = old })
	for _, kind := range []string{"form", "header", "missing"} {
		t.Run(kind, func(t *testing.T) {
			e := echo.New()
			e.Use(secureMultipart)
			e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{TokenLookup: "form:_csrf,header:X-CSRF-Token"}))
			called := false
			e.POST("/file", func(c echo.Context) error {
				called = true
				if c.FormValue("password") != "passphrase" || utils.GetSecureMultipart(c.Request()) == nil {
					t.Fatal("secure form not available")
				}
				return c.NoContent(http.StatusNoContent)
			})
			csrf := ""
			if kind == "form" {
				csrf = "csrf-value"
			}
			body, contentType := makeMultipartBody(t, csrf, 1024)
			req := httptest.NewRequest(http.MethodPost, "/file", body)
			req.Header.Set("Content-Type", contentType)
			req.AddCookie(&http.Cookie{Name: "_csrf", Value: "csrf-value"})
			if kind == "header" {
				req.Header.Set("X-CSRF-Token", "csrf-value")
			}
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if kind == "missing" {
				if called || rec.Code < 400 {
					t.Fatalf("missing CSRF accepted: %d", rec.Code)
				}
			} else if !called || rec.Code != http.StatusNoContent {
				t.Fatalf("%s token rejected: %d", kind, rec.Code)
			}
		})
	}
}

func TestSecureMultipartPreservesBodyLimitError(t *testing.T) {
	old := utils.FILEFOLDER
	utils.FILEFOLDER = t.TempDir()
	t.Cleanup(func() { utils.FILEFOLDER = old })
	e := echo.New()
	e.Use(middleware.BodyLimit("256"))
	e.Use(secureMultipart)
	e.POST("/file", func(c echo.Context) error { t.Fatal("oversized upload accepted"); return nil })
	body, contentType := makeMultipartBody(t, "csrf-value", 4096)
	req := httptest.NewRequest(http.MethodPost, "/file", body)
	req.ContentLength = -1 // Exercise the streaming limit, not Content-Length.
	req.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestSecureMultipartOversizedFieldReturns413(t *testing.T) {
	old := utils.FILEFOLDER
	utils.FILEFOLDER = t.TempDir()
	t.Cleanup(func() { utils.FILEFOLDER = old })
	body := new(bytes.Buffer)
	w := multipart.NewWriter(body)
	if err := w.WriteField("password", strings.Repeat("x", utils.MaxSecretBytes+1)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	e.Use(secureMultipart)
	e.POST("/file", func(c echo.Context) error { t.Fatal("oversized field accepted"); return nil })
	req := httptest.NewRequest(http.MethodPost, "/file", body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestSecureMultipartHTTP1RejectsStalledChunkedBodyImmediately(t *testing.T) {
	old := utils.FILEFOLDER
	utils.FILEFOLDER = t.TempDir()
	t.Cleanup(func() { utils.FILEFOLDER = old })
	e := echo.New()
	e.Use(secureMultipart)
	e.POST("/file", func(c echo.Context) error { t.Error("oversized field accepted"); return nil })
	serverConn, clientConn := net.Pipe()
	listener := &multipartPipeListener{conn: serverConn, closed: make(chan struct{})}
	server := &http.Server{Handler: e}
	finished := make(chan struct{})
	go func() { defer close(finished); _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = clientConn.Close(); _ = server.Close(); <-finished })
	// Do not send the chunk terminator or multipart end marker. After the
	// field-size violation, the request body stalls indefinitely.
	part := "--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n" + strings.Repeat("x", utils.MaxSecretBytes+8192)
	head := "POST /file HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\nContent-Type: multipart/form-data; boundary=boundary\r\n\r\n"
	written := make(chan error, 1)
	go func() { _, err := fmt.Fprintf(clientConn, "%s%x\r\n%s", head, len(part), part); written <- err }()
	if err := clientConn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(clientConn), &http.Request{Method: http.MethodPost})
	if err != nil {
		t.Fatalf("server did not reject stalled chunked upload promptly: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if !resp.Close {
		t.Fatal("HTTP/1 connection must close after rejecting an unread body")
	}
}

func TestSecureMultipartHTTP2RejectsWithoutConnectionHeader(t *testing.T) {
	old := utils.FILEFOLDER
	utils.FILEFOLDER = t.TempDir()
	t.Cleanup(func() { utils.FILEFOLDER = old })
	e := echo.New()
	e.Use(secureMultipart)
	e.POST("/file", func(c echo.Context) error { t.Error("oversized field accepted"); return nil })
	e.GET("/healthy", func(c echo.Context) error { return c.NoContent(http.StatusNoContent) })
	client := newHTTP2Pipe(t, e)
	body := new(bytes.Buffer)
	w := multipart.NewWriter(body)
	if err := w.WriteField("password", strings.Repeat("x", utils.MaxSecretBytes+8192)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://unit.invalid/file", body)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", w.FormDataContentType())
	resp, err := client.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusRequestEntityTooLarge || resp.Header.Get("Connection") != "" {
		t.Fatalf("HTTP/2 rejection: protocol=%s status=%d connection=%q", resp.Proto, resp.StatusCode, resp.Header.Get("Connection"))
	}
	check, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://unit.invalid/healthy", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err = client.RoundTrip(check)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("next stream status = %d", resp.StatusCode)
	}
}
