package router

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/flosch/pongo2"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

type selectionLimitRenderer struct{}

func (selectionLimitRenderer) Render(_ *echo.Context, w io.Writer, name string, data any) error {
	template, err := pongo2.FromFile(filepath.Join("..", "views", name))
	if err != nil {
		return err
	}
	return template.ExecuteWriter(data.(pongo2.Context), w)
}

func TestFileSelectionLimitResponses(t *testing.T) {
	oldFolder, oldSize := utils.FILEFOLDER, utils.MaxFileSize
	utils.FILEFOLDER, utils.MaxFileSize = t.TempDir(), 10
	t.Cleanup(func() { utils.FILEFOLDER, utils.MaxFileSize = oldFolder, oldSize })
	e := echo.New()
	e.Renderer = selectionLimitRenderer{}
	ConfigureErrorHandler(e, t.TempDir())
	e.Use(requestLimitsWithUploadLease(time.Minute, time.Minute, time.Minute, func(*http.Request, time.Duration) (func(), error) {
		return func() {}, nil
	}))
	e.Use(secureMultipart)
	e.POST("/file", func(*echo.Context) error { t.Fatal("rejected upload reached the handler"); return nil })
	for _, tc := range []struct {
		name, accept, mode, message, jsonCode string
		files, fileBytes, status              int
		filenames                             []string
	}{
		{"count", "text/html", "navigate", "Select no more than 100 files.", "", 101, 0, 400, nil},
		{"size", "text/html,application/xhtml+xml", "", "exceeds the size limit", "", 2, 6, 413, nil},
		{"declared body", "text/html", "navigate", "exceeds the size limit", "", 1, 0, 413, nil},
		{"invalid filename", "text/html", "navigate", "Invalid file name.", "", 1, 0, 400, []string{"bad?.txt"}},
		{"duplicate filename", "text/html", "navigate", "Duplicate file name.", "", 2, 0, 400, []string{"Straße.txt", "STRASSE.txt"}},
		{"progress invalid filename", "application/json", "cors", "Invalid file name.", utils.UploadFilenameErrorCode, 1, 0, 400, []string{"bad?.txt"}},
		{"progress duplicate filename", "application/json", "cors", "Duplicate file name.", utils.UploadFilenameErrorCode, 2, 0, 400, []string{"Straße.txt", "STRASSE.txt"}},
		{"progress size", "application/json", "cors", "exceeds the size limit", "file_selection_limit", 1, 11, 413, nil},
		{"progress count", "application/json", "cors", "Select no more than 100 files.", "file_selection_limit", 101, 0, 400, nil},
		{"progress declared body", "application/json", "cors", "exceeds the size limit", "file_selection_limit", 1, 0, 413, nil},
		{"progress oversized field", "application/json", "cors", "", "", 1, 0, 413, nil},
		{"fetch", "text/html", "cors", "", "", 1, 11, 413, nil},
		{"oversized field", "text/html", "navigate", "", "", 1, 0, 413, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body bytes.Buffer
			w := multipart.NewWriter(&body)
			for i := 0; i < tc.files; i++ {
				filename := fmt.Sprintf("test-%d.txt", i)
				if len(tc.filenames) > 0 {
					filename = tc.filenames[i]
				}
				file, err := w.CreateFormFile("files", filename)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := io.WriteString(file, strings.Repeat("a", tc.fileBytes)); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasSuffix(tc.name, "oversized field") {
				if err := w.WriteField("password", strings.Repeat("s", utils.MaxSecretBytes+1)); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/file", &body)
			req.Header.Set("Content-Type", w.FormDataContentType())
			req.Header.Set("Accept", tc.accept)
			req.Header.Set("Sec-Fetch-Mode", tc.mode)
			if strings.HasSuffix(tc.name, "declared body") {
				req.ContentLength = maxUploadBodyBytes + 1
			}
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			refresh := rec.Header().Get("Refresh")
			if rec.Code != tc.status {
				t.Fatalf("status=%d refresh=%q", rec.Code, refresh)
			}
			if tc.accept == "application/json" {
				if refresh != "" {
					t.Fatal("JSON response contains a navigation header")
				}
				if tc.message == "" {
					if strings.Contains(rec.Body.String(), "file_selection_limit") {
						t.Fatal("unrelated error marked as a file selection limit")
					}
				} else {
					var result map[string]string
					if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") || json.Unmarshal(rec.Body.Bytes(), &result) != nil ||
						result["code"] != tc.jsonCode || !strings.Contains(result["error"], tc.message) {
						t.Fatal("incorrect JSON selection error")
					}
				}
			} else if tc.mode != "cors" {
				message := tc.message
				if message == "" {
					message = http.StatusText(tc.status)
				}
				wantRefresh := "3; url=/file"
				if len(tc.filenames) != 0 {
					wantRefresh = ""
					body := rec.Body.String()
					if !strings.Contains(body, `id="file_create"`) || !strings.Contains(html.UnescapeString(body), "🚫 "+message) ||
						strings.Contains(body, "Unable to submit the form") {
						t.Fatal("filename error was not rendered in the upload form")
					}
				}
				if refresh != wantRefresh || !strings.Contains(rec.Body.String(), message) ||
					strings.Contains(rec.Body.String(), "Returning to") || strings.Contains(rec.Body.String(), "Return now") {
					t.Fatal("missing native return or selection message")
				}
			} else if refresh != "" {
				t.Fatal("fetch response contains a navigation header")
			}
			for _, filename := range tc.filenames {
				if strings.Contains(rec.Body.String(), filename) {
					t.Fatal("response exposed the supplied filename")
				}
			}
			if files, err := filepath.Glob(filepath.Join(utils.FILEFOLDER, ".okuru-multipart-*")); err != nil || len(files) != 0 {
				t.Fatalf("staging left after rejection: %v", files)
			}
		})
	}
}

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
			e.POST("/file", func(c *echo.Context) error {
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
	e.Use(middleware.BodyLimit(256))
	e.Use(secureMultipart)
	e.POST("/file", func(c *echo.Context) error { t.Fatal("oversized upload accepted"); return nil })
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
	e.POST("/file", func(c *echo.Context) error { t.Fatal("oversized field accepted"); return nil })
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
	e.POST("/file", func(c *echo.Context) error { t.Error("oversized field accepted"); return nil })
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
	e.POST("/file", func(c *echo.Context) error { t.Error("oversized field accepted"); return nil })
	e.GET("/healthy", func(c *echo.Context) error { return c.NoContent(http.StatusNoContent) })
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
