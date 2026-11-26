package controllers_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/models"
	u "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

// Fail the first ZIP write after accepting a prefix, as a disconnected client would.
type interruptedZIP struct{ http.ResponseWriter }

func (w interruptedZIP) Write(p []byte) (int, error) {
	n, err := w.ResponseWriter.Write(p[:min(7, len(p))])
	if err != nil {
		return n, err
	}
	_ = http.NewResponseController(w.ResponseWriter).Flush()
	return n, io.ErrClosedPipe
}

func TestConditionalRangeBeyondEnd(t *testing.T) {
	e := resourceTest(t)
	for _, tc := range []struct {
		name, requested, validator string
		status                     int
	}{
		{"stale tag", "bytes=999999-", `"stale"`, 200},
		{"stale date bounded", "bytes=999999-1000000", "Thu, 01 Jan 1970 00:00:00 GMT", 200},
		{"matched", "bytes=999999-", "match", 416},
		{"no validator", "bytes=999999-", "", 416},
		{"reversed bounds", "bytes=999999-999998", `"stale"`, 416},
		{"missing cookie", "bytes=999999-", `"stale"`, 404},
		{"partly spent budget", "bytes=999999-", `"stale"`, 429},
		{"changed archive", "bytes=999999-", `"stale"`, 412},
		{"mixed-case unit", "ByTeS=7-8", "match", 206},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token, filePath, archive := createHTTPContractArchive(t)
			f := &models.File{FileKey: token}
			if err := u.GetFile(f); err != nil {
				t.Fatal(err)
			}
			post := requestWithCSRF(t, e, "/file/"+token, nil)
			if post.Code != http.StatusSeeOther {
				t.Fatalf("authorization returned %d", post.Code)
			}
			location := post.Header().Get("Location")
			get := func(byteRange, validator string, authorized bool) *http.Request {
				req := httptest.NewRequest(http.MethodGet, location, nil)
				if authorized {
					for _, cookie := range post.Result().Cookies() {
						if cookie.Path == location {
							req.AddCookie(cookie)
						}
					}
				}
				req.Header.Set("Range", byteRange)
				req.Header.Set("If-Range", validator)
				return req
			}
			first := httptest.NewRecorder()
			func() {
				defer func() {
					if recovered := recover(); recovered != http.ErrAbortHandler {
						t.Fatalf("expected an interrupted initial response, got %v", recovered)
					}
				}()
				e.ServeHTTP(interruptedZIP{first}, get("", "", true))
			}()
			etag := first.Header().Get("ETag")
			validator := tc.validator
			if validator == "match" {
				validator = etag
			}
			switch tc.name {
			case "partly spent budget":
				spent := httptest.NewRecorder()
				e.ServeHTTP(spent, get("bytes=8-8", etag, true))
				if spent.Code != http.StatusPartialContent {
					t.Fatalf("range budget setup returned %d", spent.Code)
				}
			case "changed archive":
				if err := os.Rename(filePath, filePath+".old"); err != nil {
					t.Fatal(err)
				}
				writeResourceTestArchive(t, filePath, f.Password, string(archive), false)
			}
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, get(tc.requested, validator, tc.name != "missing cookie"))
			if rec.Code != tc.status {
				t.Fatalf("conditional GET returned %d, want %d", rec.Code, tc.status)
			}
			switch tc.status {
			case http.StatusOK:
				if rec.Header().Get("Content-Range") != "" || !bytes.Equal(rec.Body.Bytes(), archive) {
					t.Fatal("stale validator did not return the entire ZIP")
				}
			case http.StatusPartialContent:
				if !bytes.Equal(rec.Body.Bytes(), archive[7:9]) {
					t.Fatal("incorrect bytes for mixed-case range unit")
				}
			case http.StatusRequestedRangeNotSatisfiable:
				if tc.name != "reversed bounds" && rec.Header().Get("Content-Range") != "bytes */"+strconv.Itoa(len(archive)) {
					t.Fatal("missing ZIP length on unsatisfiable range")
				}
			}
			if tc.status >= 400 && rec.Header().Get("Content-Type") == "application/zip" {
				t.Fatal("denied request started a ZIP response")
			}
		})
	}
}

func createHTTPContractArchive(t *testing.T) (string, string, []byte) {
	t.Helper()
	identity := resourceTestIdentity(t)
	token, httpErr := u.SetFile(identity, 300, 1, true, false, "", u.ArchiveFormatAgeX25519)
	if httpErr != nil {
		t.Fatal(httpErr)
	}
	id, _, err := u.ParseToken(token)
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	zw := zip.NewWriter(&archive)
	entry, err := zw.Create("sample.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(entry, "file recovery fixture"); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	filePath := filepath.Join(u.FILEFOLDER, id+".zip")
	writeResourceTestArchive(t, filePath, identity, archive.String(), false)
	return token, filePath, archive.Bytes()
}

func authorizeDownloadFixture(t *testing.T, e *echo.Echo) (string, *http.Cookie, int) {
	t.Helper()
	token, _, archive := createHTTPContractArchive(t)
	post := requestWithCSRF(t, e, "/file/"+token, nil)
	if post.Code != http.StatusSeeOther {
		t.Fatalf("authorization returned %d", post.Code)
	}
	for _, cookie := range post.Result().Cookies() {
		if cookie.Path == post.Header().Get("Location") {
			return token, cookie, len(archive)
		}
	}
	t.Fatal("missing session cookie")
	return "", nil, 0
}

func requireEmptyDownloadResponse(t *testing.T, rec *httptest.ResponseRecorder, status int, retryAfter string) {
	t.Helper()
	if rec.Code != status || rec.Body.Len() != 0 || rec.Header().Get("Retry-After") != retryAfter {
		t.Fatalf("got status %d, %d body bytes, Retry-After %q", rec.Code, rec.Body.Len(), rec.Header().Get("Retry-After"))
	}
	if rec.Header().Get("Content-Type") == "application/zip" {
		t.Fatal("download error advertised a ZIP")
	}
	for _, header := range []string{"Content-Disposition", "Content-Range", "ETag", "Last-Modified"} {
		if rec.Header().Get(header) != "" {
			t.Fatalf("download error disclosed %s", header)
		}
	}
}

func TestDownloadPreviewDuringRedisOutage(t *testing.T) {
	e := resourceTest(t)
	token, cookie, _ := authorizeDownloadFixture(t, e)
	id, _, _ := u.ParseToken(token)
	selector := filepath.Base(cookie.Path)
	key := u.REDIS_PREFIX + "download_session_" + id + "_" + selector
	get := func(path string, credential *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		if credential != nil {
			req.AddCookie(credential)
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	if err := u.CloseRedisPool(); err != nil {
		t.Fatal(err)
	}
	pool := u.NewPool()
	pool.MaxActive = 1
	admin := pool.Get() // The read-only preview cannot borrow a connection.
	if err := admin.Err(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close(); _ = u.CloseRedisPool() })
	wrong := *cookie
	wrong.Value = "wrong"
	requireEmptyDownloadResponse(t, get(cookie.Path, nil), http.StatusNotFound, "")
	requireEmptyDownloadResponse(t, get(cookie.Path, &wrong), http.StatusNotFound, "")
	badLink := "/file/" + id + u.TOKEN_SEPARATOR + "invalid/download/" + selector
	requireEmptyDownloadResponse(t, get(badLink, cookie), http.StatusNotFound, "")
	requireEmptyDownloadResponse(t, get(cookie.Path, cookie), http.StatusServiceUnavailable, "1")

	// A syntactically valid cookie can match its selector without ever being issued.
	unissued := *cookie
	unissued.Value = strings.Repeat("A", 43) + "="
	newSelector := fmt.Sprintf("%x", sha256.Sum256([]byte(unissued.Value)))
	unissued.Name = strings.TrimSuffix(cookie.Name, selector) + newSelector
	unissued.Path = strings.TrimSuffix(cookie.Path, selector) + newSelector
	requireEmptyDownloadResponse(t, get(unissued.Path, &unissued), http.StatusServiceUnavailable, "1")
	state, err := redis.Strings(admin.Do("HMGET", key, "initial_started", "requests", "used"))
	if err != nil || strings.Join(state, ",") != "0,0,0" {
		t.Fatal("a failed preview spent a download or byte reservation")
	}
	if err := admin.Close(); err != nil {
		t.Fatal(err)
	}
	requireEmptyDownloadResponse(t, get(unissued.Path, &unissued), http.StatusNotFound, "")
	// Keep Redis available while checking independently expired and missing records.
	conn, err := redis.Dial("tcp", os.Getenv("OKURU_TEST_REDIS_ADDR"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Do("HSET", key, "idle_deadline", "1"); err != nil {
		t.Fatal(err)
	}
	requireEmptyDownloadResponse(t, get(cookie.Path, cookie), http.StatusNotFound, "")
	if _, err := conn.Do("DEL", key); err != nil {
		t.Fatal(err)
	}
	requireEmptyDownloadResponse(t, get(cookie.Path, cookie), http.StatusNotFound, "")
	if _, err := conn.Do("DEL", u.REDIS_PREFIX+"file_"+id); err != nil {
		t.Fatal(err)
	}
	requireEmptyDownloadResponse(t, get(cookie.Path, cookie), http.StatusNotFound, "")
}

type lostDownloadReplyConn struct {
	redis.ConnWithContext
	match func([]any) bool
	calls *atomic.Int32
}

func (c *lostDownloadReplyConn) Do(command string, args ...any) (any, error) {
	reply, err := c.ConnWithContext.Do(command, args...)
	return c.maybeLoseReply(command, args, reply, err)
}

func (c *lostDownloadReplyConn) DoContext(ctx context.Context, command string, args ...any) (any, error) {
	reply, err := c.ConnWithContext.DoContext(ctx, command, args...)
	return c.maybeLoseReply(command, args, reply, err)
}

func (c *lostDownloadReplyConn) maybeLoseReply(command string, args []any, reply any, err error) (any, error) {
	if err == nil && (command == "EVALSHA" || command == "EVAL") && c.match(args) && c.calls.Add(1) == 1 {
		_ = c.ConnWithContext.Close()
		return nil, io.ErrUnexpectedEOF
	}
	return reply, err
}

func TestDownloadLostRedisReply(t *testing.T) {
	for _, stage := range []string{"preview", "admission", "reservation", "additional reservation"} {
		t.Run(stage, func(t *testing.T) {
			e := resourceTest(t)
			token, cookie, size := authorizeDownloadFixture(t, e)
			req := httptest.NewRequest(http.MethodGet, cookie.Path, nil)
			req.AddCookie(cookie)
			func() {
				defer func() {
					if recover() != http.ErrAbortHandler {
						t.Fatal("initial response did not abort")
					}
				}()
				e.ServeHTTP(interruptedZIP{httptest.NewRecorder()}, req)
			}()
			id, _, _ := u.ParseToken(token)
			key := u.REDIS_PREFIX + "download_session_" + id + "_" + filepath.Base(cookie.Path)
			const length = 3
			amount := int64(length)
			if stage == "additional reservation" {
				req.Header.Set("If-Range", `"stale"`)
				amount = int64(size - length)
			}
			req.Header.Set("Range", "bytes=7-9")
			match := func(args []any) bool {
				if len(args) < 4 || args[3] != key {
					return false
				}
				switch stage {
				case "preview":
					return len(args) == 7 && args[5] == 32 && args[6] == false
				case "admission":
					return len(args) == 10 && args[6] == "3"
				}
				return len(args) == 7 && args[6] == amount
			}
			if err := u.CloseRedisPool(); err != nil {
				t.Fatal(err)
			}
			pool := u.NewPool()
			dial := pool.DialContext
			var calls atomic.Int32
			pool.DialContext = func(ctx context.Context) (redis.Conn, error) {
				c, err := dial(ctx)
				if err != nil {
					return nil, err
				}
				return &lostDownloadReplyConn{c.(redis.ConnWithContext), match, &calls}, nil
			}
			t.Cleanup(func() { _ = u.CloseRedisPool() })
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			wantRequests, wantUsed, retryAfter := 1, int(amount), ""
			switch stage {
			case "preview":
				wantRequests, wantUsed, retryAfter = 0, 0, "1"
			case "admission":
				wantUsed = 0
			}
			requireEmptyDownloadResponse(t, rec, http.StatusServiceUnavailable, retryAfter)
			if calls.Load() != 1 {
				t.Fatalf("Redis executed %s %d times", stage, calls.Load())
			}
			conn := pool.Get()
			defer conn.Close()
			state, err := redis.Ints(conn.Do("HMGET", key, "requests", "used"))
			if err != nil || len(state) != 2 || state[0] != wantRequests || state[1] != wantUsed {
				t.Fatalf("ambiguous %s left incorrect request/byte counts %v", stage, state)
			}
		})
	}
}

// Exercise the raw HTTP representation through the complete router over TLS.
// A clock-skewed archive cannot use its future timestamp as an HTTP validator.
func TestDownloadResumesOverHTTPSWithETagAlone(t *testing.T) {
	e := resourceTest(t)
	token, filePath, archive := createHTTPContractArchive(t)
	future := time.Now().Add(time.Hour)
	if err := os.Chtimes(filePath, future, future); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/download/") && r.Header.Get("Range") == "" {
			w = interruptedZIP{w}
		}
		e.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	client := server.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client.Jar = jar
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	share := server.URL + "/file/" + token
	preview, err := client.Get(share)
	if err != nil {
		t.Fatal(err)
	}
	preview.Body.Close()
	form := url.Values{}
	for _, cookie := range preview.Cookies() {
		if cookie.Name == "__Host-okuru-csrf" {
			form.Set("_csrf", cookie.Value)
		}
	}
	post, err := client.PostForm(share, form)
	if err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != http.StatusSeeOther {
		t.Fatalf("authorization returned %d", post.StatusCode)
	}
	zipPath := post.Header.Get("Location")
	downloadCookies := 0
	for _, cookie := range post.Cookies() {
		if strings.HasPrefix(cookie.Name, "__Secure-okuru-") {
			downloadCookies++
			if !strings.HasPrefix(cookie.Name, "__Secure-okuru-dl-") || cookie.Path != zipPath || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
				t.Fatal("download credential is missing its session-specific scope or security attributes")
			}
		}
	}
	if downloadCookies != 1 {
		t.Fatalf("POST issued %d download cookies, want one", downloadCookies)
	}
	get := func(offset int, validator string) (*http.Response, []byte, error) {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, server.URL+zipPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		// Supplying this explicitly keeps the Go transport from transparently decompressing.
		req.Header.Set("Accept-Encoding", "br, gzip")
		if offset > 0 {
			req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
			req.Header.Set("If-Range", validator)
		}
		res, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer res.Body.Close()
		body, err := io.ReadAll(res.Body)
		return res, body, err
	}
	first, prefix, err := get(0, "")
	if first.StatusCode != http.StatusOK || !errors.Is(err, io.ErrUnexpectedEOF) || !bytes.Equal(prefix, archive[:7]) {
		t.Fatalf("initial TLS download returned status %d with %d bytes and error %v", first.StatusCode, len(prefix), err)
	}
	etag := first.Header.Get("ETag")
	if !strings.HasPrefix(etag, `"`) || !strings.HasSuffix(etag, `"`) || len(etag) <= 2 {
		t.Fatal("initial response is missing a strong entity tag")
	}
	rest, suffix, err := get(len(prefix), etag)
	if err != nil || rest.StatusCode != http.StatusPartialContent || !bytes.Equal(append(prefix, suffix...), archive) {
		t.Fatalf("ETag-only continuation returned status %d with %d bytes and error %v", rest.StatusCode, len(suffix), err)
	}
	if first.Header.Get("Content-Range") != "" || rest.Header.Get("Content-Range") != fmt.Sprintf("bytes 7-%d/%d", len(archive)-1, len(archive)) ||
		first.Header.Get("Content-Length") != strconv.Itoa(len(archive)) || rest.Header.Get("Content-Length") != strconv.Itoa(len(suffix)) {
		t.Fatal("ZIP length or byte offsets changed in transit")
	}
	for _, response := range []*http.Response{first, rest} {
		if response.Header.Get("ETag") != etag || response.Header.Get("Last-Modified") != "" ||
			response.Header.Get("Accept-Ranges") != "bytes" || response.Header.Get("Content-Encoding") != "" ||
			response.Header.Get("Content-Type") != "application/zip" {
			t.Fatal("ZIP validators, range advertisement or content coding changed in transit")
		}
	}
}
