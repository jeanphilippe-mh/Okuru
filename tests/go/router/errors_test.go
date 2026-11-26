package router

import (
	"bytes"
	"encoding/json"
	"errors"
	"html"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
)

func TestErrorsKeepStatusAndAreWrittenOnce(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "400.html"), []byte("<p>bad input</p>"), 0600); err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	ConfigureErrorHandler(e, dir)
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		HandleError:   true,
		LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error { return nil },
	}))
	e.GET("/api/test", func(c *echo.Context) error { return echo.NewHTTPError(400, "private message") })
	e.GET("/web", func(c *echo.Context) error { return echo.NewHTTPError(400, http.StatusText(400)) })
	e.GET("/fallback", func(c *echo.Context) error { return errors.New("private failure") })
	for _, path := range []string{"/api/test", "/web", "/fallback"} {
		response := httptest.NewRecorder()
		e.ServeHTTP(response, httptest.NewRequest("GET", path, nil))
		if path == "/fallback" {
			if response.Code != 500 || response.Body.String() != "Internal Server Error" {
				t.Fatalf("bad fallback: %d %s", response.Code, response.Body)
			}
		} else if response.Code != 400 {
			t.Fatalf("lost error status: %d", response.Code)
		}
		if path == "/api/test" {
			var body map[string]string
			if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
				t.Fatal("duplicate or malformed JSON:", err)
			}
			if len(body) != 2 || body["code"] != "bad_request" || body["message"] != "Bad Request" {
				t.Fatalf("unexpected JSON: %v", body)
			}
		}
		if path == "/web" && response.Body.String() != "<p>bad input</p>" {
			t.Fatal("error HTML not served")
		}
	}
}

func TestFormNavigationErrorsReturnToOriginalForm(t *testing.T) {
	e := echo.New()
	e.Renderer = selectionLimitRenderer{}
	ConfigureErrorHandler(e, t.TempDir())
	e.Pre(func(_ echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			c.Response().Header().Set("Retry-After", "60")
			return echo.NewHTTPError(http.StatusTooManyRequests, "private detail")
		}
	})
	for _, tc := range []struct {
		method, path, mode, accept, xhr, destination string
	}{
		{http.MethodPost, "/", "navigate", echo.MIMETextHTML, "", "/"},
		{http.MethodPost, "/file", "navigate", echo.MIMETextHTML, "", "/file"},
		{http.MethodPost, "/file/", "", echo.MIMETextHTML, "", "/file"},
		{http.MethodPost, "/file", "cors", echo.MIMEApplicationJSON, "", ""},
		{http.MethodPost, "/file", "", echo.MIMETextHTML, "XMLHttpRequest", ""},
		{http.MethodPost, "/api/v2/files/direct", "navigate", echo.MIMETextHTML, "", ""},
		{http.MethodGet, "/file/key/download/session", "navigate", echo.MIMETextHTML, "", ""},
		{http.MethodHead, "/file", "navigate", echo.MIMETextHTML, "", ""},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set(echo.HeaderAccept, tc.accept)
		req.Header.Set("Sec-Fetch-Mode", tc.mode)
		req.Header.Set("X-Requested-With", tc.xhr)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" ||
			strings.Contains(rec.Body.String(), "private detail") {
			t.Fatalf("%s %s returned status=%d, headers=%v, body=%q", tc.method, tc.path, rec.Code, rec.Header(), rec.Body.String())
		}
		if tc.destination == "" {
			if rec.Header().Get("Refresh") != "" || tc.method == http.MethodHead && rec.Body.Len() != 0 {
				t.Fatalf("%s %s received an unexpected form return", tc.method, tc.path)
			}
			continue
		}
		if rec.Header().Get("Refresh") != "3; url="+tc.destination ||
			!strings.Contains(rec.Body.String(), "Too Many Requests") || strings.Contains(rec.Body.String(), `http-equiv="refresh"`) ||
			strings.Contains(rec.Body.String(), "Returning to") || strings.Contains(rec.Body.String(), "Return now") {
			t.Fatalf("%s %s has no unique form return for %s", tc.method, tc.path, tc.destination)
		}
	}
}

func TestCSRFVerificationErrorsStayOnTheirForm(t *testing.T) {
	e := New()
	e.Renderer = selectionLimitRenderer{}
	ConfigureErrorHandler(e, filepath.Join("..", "views"))
	// Produce an unrelated 403 after CSRF has allowed the request, without
	// creating a secret or file.
	e.Use(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if c.Request().Method == http.MethodPost {
				return echo.ErrForbidden
			}
			return next(c)
		}
	})
	for _, tc := range []struct {
		name, path, token, fetchSite, mode, accept, xhr, refresh string
		status                                                   int
		csrfMessage                                              bool
	}{
		{"invalid secret token", "/", "invalid", "", "navigate", echo.MIMETextHTML, "", "", 403, true},
		{"missing secret token", "/", "", "", "navigate", echo.MIMETextHTML, "", "", 400, true},
		{"invalid file token", "/file", "invalid", "", "navigate", echo.MIMETextHTML, "", "", 403, true},
		{"cross-site file request", "/file", "correct", "cross-site", "navigate", echo.MIMETextHTML, "", "", 403, true},
		{"unrelated forbidden", "/file", "correct", "", "navigate", echo.MIMETextHTML, "", "3; url=/file", 403, false},
		{"JSON response requested", "/file", "invalid", "", "cors", echo.MIMEApplicationJSON, "", "", 403, false},
		{"XHR response requested", "/file", "invalid", "", "", echo.MIMETextHTML, "XMLHttpRequest", "", 403, false},
		{"API response", "/api/v2/secrets", "", "cross-site", "navigate", echo.MIMEApplicationJSON, "", "", 403, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			form := url.Values{"password": {"unused-secret-should-not-be-rendered"}}
			if tc.token != "" {
				form.Set("_csrf", tc.token)
			}
			r := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(form.Encode()))
			r.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
			r.Header.Set(echo.HeaderAccept, tc.accept)
			if tc.fetchSite != "" {
				r.Header.Set(echo.HeaderSecFetchSite, tc.fetchSite)
			}
			r.Header.Set("Sec-Fetch-Mode", tc.mode)
			r.Header.Set("X-Requested-With", tc.xhr)
			r.AddCookie(&http.Cookie{Name: "__Host-okuru-csrf", Value: "correct"})
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, r)
			if rec.Code != tc.status || rec.Header().Get("Refresh") != tc.refresh {
				t.Fatalf("status = %d, Refresh = %q", rec.Code, rec.Header().Get("Refresh"))
			}
			body := rec.Body.String()
			if strings.Contains(body, csrfVerificationErrorText) != tc.csrfMessage {
				t.Fatalf("form verification wording present = %t, want %t", strings.Contains(body, csrfVerificationErrorText), tc.csrfMessage)
			}
			if tc.csrfMessage {
				id := "password_create"
				if tc.path == "/file" {
					id = "file_create"
				}
				if !strings.Contains(body, `id="`+id+`"`) ||
					!strings.Contains(html.UnescapeString(body), "🚫 "+csrfVerificationErrorText) ||
					strings.Contains(body, "Unable to submit the form") ||
					strings.Contains(body, "unused-secret-should-not-be-rendered") {
					t.Fatal("CSRF rejection did not restore the form with its inline alert")
				}
				if tc.fetchSite == "cross-site" {
					if len(rec.Result().Cookies()) != 0 {
						t.Fatal("cross-site rejection set a CSRF cookie")
					}
				} else {
					cookies := rec.Result().Cookies()
					if len(cookies) != 1 || cookies[0].Name != "__Host-okuru-csrf" || len(cookies[0].Value) != 32 ||
						cookies[0].Path != "/" || cookies[0].Domain != "" ||
						!cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode ||
						!strings.Contains(body, `name="_csrf" value="`+cookies[0].Value+`"`) {
						t.Fatal("rendered form did not receive a matching secure CSRF cookie")
					}
				}
			}
			if tc.path == "/api/v2/secrets" && !strings.Contains(body, `"message":"Forbidden"`) {
				t.Fatalf("unexpected API error body: %q", body)
			}
		})
	}
}

func TestUploadProgressCSRFErrorCanRefreshTheSameOriginForm(t *testing.T) {
	e := echo.New()
	ConfigureErrorHandler(e, t.TempDir())
	e.Use(secureMultipart)
	e.Use(middleware.CSRFWithConfig(browserCSRFConfig()))
	e.POST("/file", func(c *echo.Context) error {
		if c.QueryParam("deny") != "" {
			return echo.ErrForbidden
		}
		return c.NoContent(http.StatusNoContent)
	})

	request := func(path, origin, site, cookie, token string) *httptest.ResponseRecorder {
		t.Helper()
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if token != "" {
			if err := writer.WriteField("_csrf", token); err != nil {
				t.Fatal(err)
			}
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "https://share.example"+path, &body)
		req.Header.Set(echo.HeaderContentType, writer.FormDataContentType())
		req.Header.Set(echo.HeaderAccept, echo.MIMEApplicationJSON)
		req.Header.Set(echo.HeaderOrigin, origin)
		req.Header.Set(echo.HeaderSecFetchSite, site)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: "__Host-okuru-csrf", Value: cookie})
		}
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		return rec
	}
	assertCSRFError := func(rec *httptest.ResponseRecorder, status int) {
		t.Helper()
		var response map[string]string
		if rec.Code != status || rec.Header().Get("Refresh") != "" ||
			rec.Header().Get(echo.HeaderCacheControl) != "private, no-store" ||
			rec.Header().Get("Access-Control-Allow-Origin") != "" ||
			json.Unmarshal(rec.Body.Bytes(), &response) != nil || len(response) != 2 ||
			response["code"] != csrfVerificationErrorCode || response["error"] != csrfVerificationErrorText {
			t.Fatalf("unexpected progress CSRF response: status %d, headers %v, body %q", rec.Code, rec.Header(), rec.Body.String())
		}
	}

	ownOrigin := "https://share.example"
	rec := request("/file", ownOrigin, "", "", "")
	assertCSRFError(rec, http.StatusBadRequest)
	token := rec.Header().Get(echo.HeaderXCSRFToken)
	cookies := rec.Result().Cookies()
	if len(token) != 32 || len(cookies) != 1 || cookies[0].Name != "__Host-okuru-csrf" ||
		cookies[0].Path != "/" || cookies[0].Domain != "" ||
		cookies[0].Value != token || !cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("same-origin rejection did not issue a matching secure CSRF token")
	}
	if got := request("/file", ownOrigin, "", token, token); got.Code != http.StatusNoContent {
		t.Fatalf("renewed token was not accepted: %d", got.Code)
	}

	rec = request("/file", ownOrigin, "", token, "incorrect")
	assertCSRFError(rec, http.StatusForbidden)
	if rec.Header().Get(echo.HeaderXCSRFToken) != token || len(rec.Result().Cookies()) != 0 {
		t.Fatal("existing valid CSRF cookie was not reused")
	}

	for _, tc := range []struct{ origin, site string }{
		{"https://external.example", "cross-site"},
		{"https://external.example", ""},
		{"", ""},
	} {
		rec = request("/file", tc.origin, tc.site, token, "incorrect")
		assertCSRFError(rec, http.StatusForbidden)
		if rec.Header().Get(echo.HeaderXCSRFToken) != "" || len(rec.Result().Cookies()) != 0 {
			t.Fatal("unverified origin received a token or cookie")
		}
	}

	rec = request("/file?deny=1", ownOrigin, "", token, token)
	if rec.Code != http.StatusForbidden || rec.Header().Get(echo.HeaderXCSRFToken) != "" ||
		strings.Contains(rec.Body.String(), csrfVerificationErrorCode) {
		t.Fatal("unrelated 403 received CSRF recovery metadata")
	}
}

func TestBrowserMultipartFetchMetadataRejectsBeforeAdmission(t *testing.T) {
	e := New()
	e.Renderer = selectionLimitRenderer{}
	ConfigureErrorHandler(e, t.TempDir())
	for _, tc := range []struct {
		name, path, site, accept string
		protocol                 int
	}{
		{"JSON over HTTP/1", "/file", "cross-site", echo.MIMEApplicationJSON, 1},
		{"HTML with trailing slash", "/file/", "cross-site", echo.MIMETextHTML, 1},
		{"unrecognized metadata over HTTP/2", "/file", "unrecognized", echo.MIMEApplicationJSON, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, tc.path, unexpectedUploadRead{t})
			req.ProtoMajor = tc.protocol
			// The request admission middleware would otherwise reject this
			// length before acquiring a lease. Expect the earlier CSRF error.
			req.ContentLength = maxUploadBodyBytes + 1
			req.Header.Set(echo.HeaderContentType, "multipart/form-data; boundary=fixture")
			req.Header.Set(echo.HeaderSecFetchSite, tc.site)
			req.Header.Set(echo.HeaderAccept, tc.accept)
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden || rec.Header().Get(echo.HeaderXCSRFToken) != "" ||
				rec.Header().Get(echo.HeaderCacheControl) != "private, no-store" || len(rec.Result().Cookies()) != 0 {
				t.Fatalf("unexpected CSRF rejection: status=%d, headers=%v", rec.Code, rec.Header())
			}
			if got := rec.Header().Get(echo.HeaderConnection); (tc.protocol == 1 && got != "close") || (tc.protocol == 2 && got != "") {
				t.Fatalf("unexpected Connection header for HTTP/%d: %q", tc.protocol, got)
			}
			if tc.accept == echo.MIMETextHTML {
				body := html.UnescapeString(rec.Body.String())
				if !strings.Contains(body, `id="file_create"`) || !strings.Contains(body, "🚫 "+csrfVerificationErrorText) {
					t.Fatal("HTML rejection did not preserve inline form feedback")
				}
				return
			}
			var body map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || len(body) != 2 ||
				body["code"] != csrfVerificationErrorCode || body["error"] != csrfVerificationErrorText {
				t.Fatalf("unexpected JSON CSRF error: %q", rec.Body.String())
			}
		})
	}
}

func TestHTTP413PagesDisplayOnlyTheirKnownSizeLimit(t *testing.T) {
	oldMax := utils.MaxFileSize
	utils.MaxFileSize = 1536 * 1024 * 1024
	t.Cleanup(func() { utils.MaxFileSize = oldMax })
	e := New()
	e.Renderer = selectionLimitRenderer{}
	ConfigureErrorHandler(e, filepath.Join("..", "views"))
	e.GET("/generic-size-error", func(*echo.Context) error { return echo.ErrStatusRequestEntityTooLarge })

	assertPage := func(t *testing.T, path string, includesLimit bool) {
		t.Helper()
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		body := rec.Body.String()
		if rec.Code != http.StatusRequestEntityTooLarge ||
			!strings.Contains(body, "🚫 The request exceeds the server’s size limit.") ||
			!strings.Contains(body, `http-equiv="refresh" content="3; url=/"`) ||
			strings.Contains(body, "{{") || strings.Contains(body, "{%") ||
			strings.Contains(body, "1536 MB") != includesLimit {
			t.Fatalf("%s returned HTTP %d with unexpected 413 page", path, rec.Code)
		}
	}
	assertPage(t, "/413.html", true)
	assertPage(t, "/file/413.html", true)
	assertPage(t, "/generic-size-error", false)
	// The copy installed by Apache is also available as the Go fallback.
	e.Renderer = nil
	assertPage(t, "/generic-size-error", false)
}
