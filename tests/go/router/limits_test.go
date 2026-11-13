package router

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
)

type deadlineRecorder struct {
	*httptest.ResponseRecorder
	readDeadlines  []time.Time
	writeDeadlines []time.Time
}

// Protocol and timeout tests inject a no-op lease; separate Redis-backed tests
// exercise the actual multi-process admission and its integration below.
func testRequestLimits(idle, read, write time.Duration) echo.MiddlewareFunc {
	return requestLimitsWithUploadLease(idle, read, write, func(*http.Request, time.Duration) (func(), error) {
		return func() {}, nil
	})
}

func (r *deadlineRecorder) SetReadDeadline(deadline time.Time) error {
	r.readDeadlines = append(r.readDeadlines, deadline)
	return nil
}

func (r *deadlineRecorder) SetWriteDeadline(deadline time.Time) error {
	r.writeDeadlines = append(r.writeDeadlines, deadline)
	return nil
}

func TestSmallRequestLimitPrecedesLaterMiddleware(t *testing.T) {
	for _, unknownLength := range []bool{false, true} {
		e := echo.New()
		e.Use(testRequestLimits(time.Minute, time.Hour, time.Hour))
		called := false
		e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
			return func(c echo.Context) error { called = true; return next(c) }
		})
		e.POST("/", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", maxSmallRequestBytes+1)))
		if unknownLength {
			req.ContentLength = -1
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusRequestEntityTooLarge || called {
			t.Fatalf("unknownLength=%v status=%d later middleware=%v", unknownLength, rec.Code, called)
		}
	}
}

func TestSmallBodyIsPreservedForHandler(t *testing.T) {
	e := echo.New()
	e.Use(testRequestLimits(time.Minute, time.Hour, time.Hour))
	e.POST("/api/v1", func(c echo.Context) error {
		body, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return err
		}
		return c.String(http.StatusOK, string(body))
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1", strings.NewReader(`{"password":"secret"}`))
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Body.String() != `{"password":"secret"}` {
		t.Fatalf("request was changed: status=%d body=%q", rec.Code, rec.Body.String())
	}
}

func TestMultipartUploadKeepsLargerBodyAllowance(t *testing.T) {
	oldFolder := utils.FILEFOLDER
	utils.FILEFOLDER = t.TempDir()
	t.Cleanup(func() { utils.FILEFOLDER = oldFolder })
	e := echo.New()
	e.Use(testRequestLimits(time.Minute, time.Hour, time.Hour))
	e.POST("/file", func(c echo.Context) error {
		data, err := io.ReadAll(c.Request().Body)
		if err != nil {
			return err
		}
		if len(data) != maxSmallRequestBytes+1 {
			t.Fatalf("body truncated: %d", len(data))
		}
		return c.NoContent(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPost, "/file", strings.NewReader(strings.Repeat("x", maxSmallRequestBytes+1)))
	req.Header.Set(echo.HeaderContentType, "multipart/form-data; boundary=test")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload rejected: %d", rec.Code)
	}
}

func TestUploadConcurrencyIsBounded(t *testing.T) {
	oldFolder := utils.FILEFOLDER
	utils.FILEFOLDER = t.TempDir()
	t.Cleanup(func() { utils.FILEFOLDER = oldFolder })
	e := echo.New()
	e.Use(testRequestLimits(time.Minute, time.Hour, time.Hour))
	started := make(chan struct{}, maxConcurrentUploads)
	release := make(chan struct{})
	var wg sync.WaitGroup
	e.POST("/file", func(c echo.Context) error {
		started <- struct{}{}
		<-release
		return c.NoContent(http.StatusOK)
	})
	for i := 0; i < maxConcurrentUploads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/file", nil)
			req.Header.Set(echo.HeaderContentType, "multipart/form-data; boundary=test")
			e.ServeHTTP(httptest.NewRecorder(), req)
		}()
	}
	for i := 0; i < maxConcurrentUploads; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			wg.Wait()
			t.Fatal("upload did not start")
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/file", nil)
	req.Header.Set(echo.HeaderContentType, "multipart/form-data; boundary=test")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	close(release)
	wg.Wait()
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status: %d", rec.Code)
	}
}

func TestUploadLeaseAdmissionFailsClosed(t *testing.T) {
	for _, tt := range []struct {
		name   string
		err    error
		status int
	}{
		{"busy", ErrUploadLeaseBusy, http.StatusTooManyRequests},
		{"unavailable", errors.New("simulated outage"), http.StatusServiceUnavailable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e := echo.New()
			e.Use(requestLimitsWithUploadLease(time.Minute, time.Hour, time.Hour, func(*http.Request, time.Duration) (func(), error) {
				return nil, tt.err
			}))
			called := false
			e.POST("/file", func(c echo.Context) error { called = true; return c.NoContent(http.StatusOK) })
			req := httptest.NewRequest(http.MethodPost, "/file", nil)
			req.Header.Set(echo.HeaderContentType, "multipart/form-data; boundary=test")
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if rec.Code != tt.status || called {
				t.Fatalf("status=%d called=%v", rec.Code, called)
			}
		})
	}
}

func TestUploadLeaseIsEnforcedByRequestMiddleware(t *testing.T) {
	configureLeaseTestRedis(t)
	oldFolder := utils.FILEFOLDER
	utils.FILEFOLDER = t.TempDir()
	t.Cleanup(func() { utils.FILEFOLDER = oldFolder })
	r := httptest.NewRequest(http.MethodPost, "/file", nil)
	r.RemoteAddr = "192.0.2.9:1234"
	r.Header.Set(echo.HeaderContentType, "multipart/form-data; boundary=test")
	release, err := acquireUploadLease(r, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	e := echo.New()
	e.Use(requestLimits(time.Minute, time.Hour, time.Hour))
	e.POST("/file", func(c echo.Context) error { return c.NoContent(http.StatusNoContent) })
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, r)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("same client should be limited, got %d", rec.Code)
	}
	release()
	r2 := httptest.NewRequest(http.MethodPost, "/file", nil)
	r2.RemoteAddr = "192.0.2.9:1235"
	r2.Header.Set(echo.HeaderContentType, "multipart/form-data; boundary=test")
	rec = httptest.NewRecorder()
	e.ServeHTTP(rec, r2)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("released client should be accepted, got %d", rec.Code)
	}
}

func TestUploadQuotaRejectsBeforeParsing(t *testing.T) {
	oldFolder := utils.FILEFOLDER
	utils.FILEFOLDER = t.TempDir()
	t.Cleanup(func() { utils.FILEFOLDER = oldFolder })
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", "1")
	e := echo.New()
	e.Use(testRequestLimits(time.Minute, time.Hour, time.Hour))
	called := false
	e.POST("/file", func(c echo.Context) error { called = true; return c.NoContent(http.StatusOK) })
	req := httptest.NewRequest(http.MethodPost, "/file", strings.NewReader("body"))
	req.Header.Set(echo.HeaderContentType, "multipart/form-data; boundary=test")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusInsufficientStorage || called {
		t.Fatalf("quota status=%d, handler called=%v", rec.Code, called)
	}
}

func TestIdleDeadlineNeverExtendsAbsoluteDeadline(t *testing.T) {
	absolute := time.Now().Add(time.Second)
	b := idleDeadlineBody{timeout: time.Hour, absolute: absolute}
	w := idleDeadlineWriter{timeout: time.Hour, absolute: absolute}
	if !b.deadline().Equal(absolute) || !w.deadline().Equal(absolute) {
		t.Fatal("idle timeout extended the absolute deadline")
	}
}

func TestUploadRateDeadlineUsesCumulativeProgress(t *testing.T) {
	start := time.Now().Add(-2 * time.Second)
	b := idleDeadlineBody{
		timeout:   time.Hour,
		absolute:  time.Now().Add(time.Hour),
		rateStart: start,
		rateGrace: time.Second,
		minRate:   1024,
	}
	if got := b.deadline(); got.After(time.Now()) {
		t.Fatalf("zero progress received an extended deadline: %v", got)
	}
	b.bytesRead = 4096
	want := start.Add(5 * time.Second)
	if got := b.deadline(); !got.Equal(want) {
		t.Fatalf("rate deadline = %v, want %v", got, want)
	}
	b.absolute = start.Add(3 * time.Second)
	if got := b.deadline(); !got.Equal(b.absolute) {
		t.Fatalf("rate deadline exceeded absolute deadline: %v", got)
	}
}

func TestUploadRateDeadlineStopsTricklingBody(t *testing.T) {
	result := make(chan error, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		body := &idleDeadlineBody{
			ReadCloser: r.Body,
			controller: http.NewResponseController(w),
			timeout:    5 * time.Second,
			absolute:   start.Add(5 * time.Second),
			rateStart:  start,
			rateGrace:  100 * time.Millisecond,
			minRate:    1024,
		}
		_, err := io.Copy(io.Discard, body)
		result <- err
		w.WriteHeader(http.StatusRequestTimeout)
	}))
	defer server.Close()
	reader, writer := io.Pipe()
	defer writer.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL, reader)
	if err != nil {
		t.Fatal(err)
	}
	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		response, requestErr := server.Client().Do(req)
		if requestErr == nil {
			_ = response.Body.Close()
		}
	}()
	go func() { _, _ = writer.Write([]byte("x")) }()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("trickling upload unexpectedly finished without timeout")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("trickling upload was not stopped by its rate deadline")
	}
	_ = writer.Close()
	<-clientDone
}

func TestRejectedBodyHasReadDeadlineBeforeAnyRead(t *testing.T) {
	e := echo.New()
	e.Use(testRequestLimits(time.Minute, time.Hour, time.Hour))
	e.POST("/", func(c echo.Context) error { t.Fatal("handler should not run"); return nil })
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(strings.Repeat("x", maxSmallRequestBytes+1)))
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || len(rec.readDeadlines) == 0 || rec.readDeadlines[0].IsZero() {
		t.Fatalf("body rejection did not retain a read deadline: status=%d deadlines=%v", rec.Code, rec.readDeadlines)
	}
}

func TestCompletedBodyClearsItsReadDeadline(t *testing.T) {
	e := echo.New()
	e.Use(testRequestLimits(time.Minute, time.Hour, time.Hour))
	e.POST("/", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("field=value"))
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || len(rec.readDeadlines) < 2 || !rec.readDeadlines[len(rec.readDeadlines)-1].IsZero() {
		t.Fatalf("finished body retained a deadline: status=%d deadlines=%v", rec.Code, rec.readDeadlines)
	}
}
