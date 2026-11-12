package router

import (
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
		e.Use(requestLimits(time.Minute, time.Hour, time.Hour))
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
	e.Use(requestLimits(time.Minute, time.Hour, time.Hour))
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
	e.Use(requestLimits(time.Minute, time.Hour, time.Hour))
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
	e.Use(requestLimits(time.Minute, time.Hour, time.Hour))
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

func TestUploadQuotaRejectsBeforeParsing(t *testing.T) {
	oldFolder := utils.FILEFOLDER
	utils.FILEFOLDER = t.TempDir()
	t.Cleanup(func() { utils.FILEFOLDER = oldFolder })
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", "1")
	e := echo.New()
	e.Use(requestLimits(time.Minute, time.Hour, time.Hour))
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

func TestRejectedBodyHasReadDeadlineBeforeAnyRead(t *testing.T) {
	e := echo.New()
	e.Use(requestLimits(time.Minute, time.Hour, time.Hour))
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
	e.Use(requestLimits(time.Minute, time.Hour, time.Hour))
	e.POST("/", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("field=value"))
	rec := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || len(rec.readDeadlines) < 2 || !rec.readDeadlines[len(rec.readDeadlines)-1].IsZero() {
		t.Fatalf("finished body retained a deadline: status=%d deadlines=%v", rec.Code, rec.readDeadlines)
	}
}
