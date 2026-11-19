package controllers_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flosch/pongo2"
	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/models"
	u "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

type shortLinkCaptureRenderer struct {
	link          string
	fileLink      string
	passwordLink  string
	deleteSecret  string
	deleteFile    string
	previewDelete string
}

func (r *shortLinkCaptureRenderer) Render(_ *echo.Context, w io.Writer, name string, data interface{}) error {
	if name == "confirm.html" {
		values, ok := data.(pongo2.Context)
		if !ok {
			return fmt.Errorf("unexpected render context")
		}
		p, ok := values["p"].(*models.Password)
		if !ok {
			return fmt.Errorf("unexpected password model")
		}
		r.link = p.Link
		if _, ok := values["originalLink"]; ok {
			return fmt.Errorf("unexpected original secret link in render context")
		}
		r.deleteSecret, _ = values["deletableURL"].(string)
	}
	if name == "confirm_file.html" {
		values, ok := data.(pongo2.Context)
		if !ok {
			return fmt.Errorf("unexpected file render context")
		}
		f, ok := values["f"].(*models.File)
		if !ok {
			return fmt.Errorf("unexpected file model")
		}
		r.fileLink = f.Link
		r.passwordLink, _ = values["passwordLink"].(string)
		if _, ok := values["originalFileLink"]; ok {
			return fmt.Errorf("unexpected original file link in render context")
		}
		if _, ok := values["originalPasswordLink"]; ok {
			return fmt.Errorf("unexpected original file password link in render context")
		}
		r.deleteFile, _ = values["deletableURL"].(string)
	}
	if name == "password.html" || name == "file.html" {
		values, ok := data.(pongo2.Context)
		if !ok {
			return fmt.Errorf("unexpected preview render context")
		}
		r.previewDelete, _ = values["deletableURL"].(string)
	}
	_, err := io.WriteString(w, "test page")
	return err
}

func TestShortLinkConfirmationTemplatesHideOriginalLinks(t *testing.T) {
	loader, err := pongo2.NewLocalFileSystemLoader("../views")
	if err != nil {
		t.Fatal(err)
	}
	set := pongo2.NewSet("short-link-confirmation-test", loader)
	for _, tc := range []struct {
		name string
		data pongo2.Context
		want []string
	}{
		{"confirm.html", pongo2.Context{"p": &models.Password{Link: "/short-secret"}, "originalLink": "original-secret-sentinel"}, []string{"/short-secret", `data-clipboard-target="#password-link"`}},
		{"confirm_file.html", pongo2.Context{"f": &models.File{Link: "/short-file"}, "passwordLink": "/short-password", "originalFileLink": "original-file-sentinel", "originalPasswordLink": "original-password-sentinel"}, []string{"/short-file", "/short-password", `data-clipboard-target="#file-link"`, `data-clipboard-target="#password-link"`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmpl, err := set.FromFile(tc.name)
			if err != nil {
				t.Fatal(err)
			}
			result, err := tmpl.Execute(tc.data)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range tc.want {
				if !strings.Contains(result, want) {
					t.Errorf("confirmation page missing %q", want)
				}
			}
			if strings.Contains(result, "original-") || strings.Contains(result, "Original link") || strings.Contains(result, "Original file link") || strings.Contains(result, "Original password link") {
				t.Error("confirmation page exposed an original-link section")
			}
		})
	}
}

func shortLinkWebTest(t *testing.T) *echo.Echo {
	t.Helper()
	e := resourceTest(t)
	t.Setenv("OKURU_SHORTLINK_REDIS_DB", "12")
	t.Setenv("OKURU_SHORTLINK_PUBLIC_ORIGIN", "https://share.example.test")
	t.Setenv("OKURU_SHORTLINK_BITS", "128")
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	t.Cleanup(func() {
		c, err := redis.Dial("tcp", addr, redis.DialDatabase(12))
		if err == nil {
			defer c.Close()
			for _, pattern := range []string{"resource_security_short_v2_*"} {
				keys, _ := redis.Strings(c.Do("KEYS", pattern))
				for _, key := range keys {
					_, _ = c.Do("DEL", key)
				}
			}
		}
		_ = u.CloseShortLinkPool()
	})
	return e
}

// A root short URL is exactly one canonical, unpadded base64url encoding of
// 16 random bytes. Checking the whole shape distinguishes it from long links.
func requireRootShortLink(t *testing.T, link string) *url.URL {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.Host != "share.example.test" || u.RawQuery != "" || u.Fragment != "" {
		t.Fatal("short URL has an unexpected origin or query")
	}
	alias := strings.TrimPrefix(u.Path, "/")
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(alias)
	if u.Path != "/"+alias || len(alias) != 22 || err != nil || len(decoded) != 16 || base64.RawURLEncoding.EncodeToString(decoded) != alias {
		t.Fatal("short URL is not a canonical 128-bit alias at the root")
	}
	return u
}

func requireLongSecretLink(t *testing.T, link string) {
	t.Helper()
	parsed, err := url.Parse(link)
	if err != nil {
		t.Fatal("invalid long URL")
	}
	if _, _, err := u.ParseToken(strings.TrimPrefix(parsed.Path, "/")); err != nil {
		t.Fatal("fallback did not contain a valid original share token")
	}
}

// Resolve a synthetic short URL without following the redirect or consuming a
// view, so integration tests can verify the existing long-link behavior.
func shortLinkDestination(t *testing.T, e *echo.Echo, link string) *url.URL {
	t.Helper()
	short := requireRootShortLink(t, link)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, short.Path, nil))
	destination, err := url.Parse(rec.Header().Get("Location"))
	if rec.Code != http.StatusFound || err != nil || destination.IsAbs() || destination.Host != "" || !strings.HasPrefix(destination.Path, "/") {
		t.Fatal("short link did not redirect to a local destination")
	}
	return destination
}

func TestShortLinkWebSecretRoundTripAndViews(t *testing.T) {
	e := shortLinkWebTest(t)
	renderer := &shortLinkCaptureRenderer{}
	e.Renderer = renderer
	created := requestWithCSRF(t, e, "/", url.Values{"password": {"synthetic-secret"}, "ttl": {"1"}, "ttlViews": {"2"}})
	if created.Code != http.StatusOK {
		t.Fatalf("share creation failed: status %d", created.Code)
	}
	shortURL := requireRootShortLink(t, renderer.link)
	longURL := shortLinkDestination(t, e, renderer.link)
	token := strings.TrimPrefix(longURL.Path, "/")
	requireLongSecretLink(t, longURL.Path)
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(method, shortURL.Path, nil))
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != longURL.Path {
			t.Fatalf("%s redirect status=%d", method, rec.Code)
		}
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("%s redirect omitted privacy headers", method)
		}
	}
	// Redirects and the ordinary share preview must not consume a view.
	preview := httptest.NewRecorder()
	e.ServeHTTP(preview, httptest.NewRequest(http.MethodGet, longURL.Path, nil))
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d", preview.Code)
	}
	headPreview := httptest.NewRecorder()
	e.ServeHTTP(headPreview, httptest.NewRequest(http.MethodHead, longURL.Path, nil))
	if headPreview.Code != http.StatusMethodNotAllowed {
		t.Fatalf("long-link HEAD changed behavior: status=%d", headPreview.Code)
	}
	p := &models.Password{PasswordKey: token}
	if err := u.GetPassword(p); err != nil || p.Views != 2 {
		t.Fatal("redirect or preview changed remaining views")
	}
	for i := 0; i < 2; i++ {
		rec := requestWithCSRF(t, e, longURL.Path, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("reveal %d status=%d", i, rec.Code)
		}
	}
	last := requestWithCSRF(t, e, longURL.Path, nil)
	if last.Code != http.StatusNotFound {
		t.Fatalf("exhausted share returned %d", last.Code)
	}
	// The alias may remain until TTL, but the original share remains the authority.
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, shortURL.Path, nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("unexpired alias returned %d", rec.Code)
	}
	dead := httptest.NewRecorder()
	e.ServeHTTP(dead, httptest.NewRequest(http.MethodGet, rec.Header().Get("Location"), nil))
	if dead.Code != http.StatusForbidden {
		t.Fatalf("alias revived exhausted share: %d", dead.Code)
	}
}

func TestShortLinkWebFileRedirectAndDownload(t *testing.T) {
	e := shortLinkWebTest(t)
	identity := resourceTestIdentity(t)
	token, err := u.SetFile(identity, 120, 1, true, false, "", u.ArchiveFormatAgeX25519)
	if err != nil {
		t.Fatal(err)
	}
	id, _, parseErr := u.ParseToken(token)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	writeResourceTestArchive(t, filepath.Join(u.FILEFOLDER, id+".zip"), identity, "file-content", false)
	alias, createErr := u.CreateShortLink(context.Background(), token, true)
	if createErr != nil {
		t.Fatal(createErr)
	}
	t.Setenv("OKURU_SHORTLINK_BITS", "256")
	strongAlias, createErr := u.CreateShortLink(t.Context(), token, true)
	if createErr != nil {
		t.Fatal(createErr)
	}
	for _, candidate := range []string{alias, strongAlias} {
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, httptest.NewRequest(method, "/"+candidate, nil))
			if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/file/"+token {
				t.Fatalf("file %s redirect failed: %d", method, rec.Code)
			}
		}
	}
	preview := httptest.NewRecorder()
	e.ServeHTTP(preview, httptest.NewRequest(http.MethodGet, "/file/"+token, nil))
	if preview.Code != http.StatusOK {
		t.Fatalf("file preview status=%d", preview.Code)
	}
	download := requestWithCSRF(t, e, "/file/"+token, nil)
	if download.Code != http.StatusOK || download.Body.String() != "file-content" {
		t.Fatalf("file download status=%d", download.Code)
	}
}

func TestShortLinkRootVariantsAndRemovedPrefix(t *testing.T) {
	e := shortLinkWebTest(t)
	token, err := u.SetPassword("synthetic-secret", 120, 2, false)
	if err != nil {
		t.Fatal(err)
	}
	alias, createErr := u.CreateShortLink(context.Background(), token, false)
	if createErr != nil {
		t.Fatal(createErr)
	}
	t.Setenv("OKURU_SHORTLINK_BITS", "256")
	strongAlias, createErr := u.CreateShortLink(t.Context(), token, false)
	if createErr != nil {
		t.Fatal(createErr)
	}
	for _, candidate := range []string{alias, strongAlias} {
		encoded := fmt.Sprintf("/%%%02X%s", candidate[0], candidate[1:])
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			for _, path := range []string{"/" + candidate, "/" + candidate + "/", encoded} {
				rec := httptest.NewRecorder()
				e.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
				if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/"+token {
					t.Fatalf("%s alias variant %q did not resolve: status=%d", method, path, rec.Code)
				}
				if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
					t.Fatalf("%s alias variant %q omitted privacy headers", method, path)
				}
			}
			legacy := httptest.NewRecorder()
			e.ServeHTTP(legacy, httptest.NewRequest(method, "/s/"+candidate, nil))
			if legacy.Code >= 300 && legacy.Code < 400 || legacy.Header().Get("Location") == "/"+token {
				t.Fatalf("removed /s/ route resolved on %s: status=%d", method, legacy.Code)
			}
		}
	}
	// Ordinary named routes must still resolve through their original handler.
	privacy := httptest.NewRecorder()
	e.ServeHTTP(privacy, httptest.NewRequest(http.MethodGet, "/privacy-policy", nil))
	if privacy.Code != http.StatusOK {
		t.Fatalf("named route changed behavior: status=%d", privacy.Code)
	}
}

func TestShortLinkConfiguredLengthsRemainResolvableAcrossChanges(t *testing.T) {
	e := shortLinkWebTest(t)
	renderer := &shortLinkCaptureRenderer{}
	e.Renderer = renderer
	links := make(map[string]*url.URL)
	for _, tc := range []struct {
		bits string
		size int
	}{{"128", 16}, {"256", 32}} {
		t.Setenv("OKURU_SHORTLINK_BITS", tc.bits)
		rec := requestWithCSRF(t, e, "/", url.Values{"password": {"synthetic-secret"}, "ttl": {"1"}, "ttlViews": {"2"}})
		if rec.Code != http.StatusOK {
			t.Fatalf("%s-bit share creation failed: %d", tc.bits, rec.Code)
		}
		link, err := url.Parse(renderer.link)
		if err != nil || link.Scheme != "https" || link.Host != "share.example.test" || !strings.HasPrefix(link.Path, "/") {
			t.Fatalf("invalid %s-bit link", tc.bits)
		}
		alias := strings.TrimPrefix(link.Path, "/")
		seed, err := base64.RawURLEncoding.Strict().DecodeString(alias)
		if err != nil || len(seed) != tc.size || base64.RawURLEncoding.EncodeToString(seed) != alias {
			t.Fatalf("%s-bit link does not contain a canonical %d-byte alias", tc.bits, tc.size)
		}
		links[tc.bits] = link
	}
	// Changing or misconfiguring generation must not break already-issued links.
	for _, setting := range []string{"128", "256", "invalid"} {
		t.Setenv("OKURU_SHORTLINK_BITS", setting)
		for bits, link := range links {
			for _, method := range []string{http.MethodGet, http.MethodHead} {
				rec := httptest.NewRecorder()
				e.ServeHTTP(rec, httptest.NewRequest(method, link.Path, nil))
				if rec.Code != http.StatusFound {
					t.Fatalf("%s-bit alias with configuration %q and %s: status=%d", bits, setting, method, rec.Code)
				}
				requireLongSecretLink(t, rec.Header().Get("Location"))
				if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
					t.Fatalf("%s-bit alias with configuration %q omitted privacy headers", bits, setting)
				}
			}
		}
	}
}

func TestShortLinkInvalidBitsFallsBackToLongLink(t *testing.T) {
	e := shortLinkWebTest(t)
	t.Setenv("OKURU_SHORTLINK_BITS", "192")
	renderer := &shortLinkCaptureRenderer{}
	e.Renderer = renderer
	rec := requestWithCSRF(t, e, "/", url.Values{"password": {"synthetic-secret"}, "ttl": {"1"}, "ttlViews": {"1"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("invalid alias size must not prevent share creation: %d", rec.Code)
	}
	requireLongSecretLink(t, renderer.link)
}

func TestShortLinkStaticMiddlewareDoesNotHideAliases(t *testing.T) {
	e := shortLinkWebTest(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	public := filepath.Join(filepath.Dir(exe), "public")
	if err := os.Mkdir(public, 0700); err != nil {
		if os.IsExist(err) {
			t.Skip("test executable already has a public directory")
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(public) })
	if err := os.WriteFile(filepath.Join(public, "index.html"), []byte("static fallback sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(public, "fixture.css"), []byte("static asset sentinel"), 0600); err != nil {
		t.Fatal(err)
	}
	asset := httptest.NewRecorder()
	e.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/fixture.css", nil))
	if asset.Code != http.StatusOK || asset.Body.String() != "static asset sentinel" {
		t.Fatal("static asset was not served normally")
	}
	for _, size := range []int{16, 32} {
		unknown := base64.RawURLEncoding.EncodeToString(make([]byte, size))
		// The alias namespace is reserved even if a future static file has the
		// same root name; otherwise the static middleware could shadow aliases.
		if err := os.WriteFile(filepath.Join(public, unknown), []byte("collision sentinel"), 0600); err != nil {
			t.Fatal(err)
		}
		for _, method := range []string{http.MethodGet, http.MethodHead} {
			rec := httptest.NewRecorder()
			e.ServeHTTP(rec, httptest.NewRequest(method, "/"+unknown, nil))
			if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "static fallback sentinel") || strings.Contains(rec.Body.String(), "collision sentinel") {
				t.Fatalf("static HTML5 fallback intercepted %s unknown alias size %d: status=%d", method, size, rec.Code)
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatalf("static middleware caused missing privacy headers for %s alias size %d", method, size)
			}
		}
	}
}

func TestShortLinkWebPrivacyHeadersOnFailure(t *testing.T) {
	e := shortLinkWebTest(t)
	unknown := base64.RawURLEncoding.EncodeToString(make([]byte, 16))
	oldUnknown := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	noncanonical := strings.Repeat("A", 21) + "B"
	oldNoncanonical := strings.Repeat("A", 42) + "B"
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/" + unknown}, {http.MethodHead, "/" + unknown},
		{http.MethodPost, "/" + unknown}, {http.MethodGet, "/" + noncanonical},
		{http.MethodGet, "/" + oldUnknown}, {http.MethodHead, "/" + oldUnknown},
		{http.MethodPost, "/" + oldUnknown}, {http.MethodGet, "/" + oldNoncanonical},
	} {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("missing privacy headers on %s %s", tc.method, tc.path)
		}
		if rec.Code >= 200 && rec.Code < 400 {
			t.Fatalf("malformed alias unexpectedly succeeded: %d", rec.Code)
		}
	}
}

func TestShortLinkWebFallbackForUntrustedOrigin(t *testing.T) {
	for _, origin := range []string{"", "http://share.example.test", "https://share.example.test/path", "https://user@share.example.test", "https://share.example.test?x=1"} {
		t.Run(origin, func(t *testing.T) {
			e := shortLinkWebTest(t)
			t.Setenv("OKURU_SHORTLINK_PUBLIC_ORIGIN", origin)
			renderer := &shortLinkCaptureRenderer{}
			e.Renderer = renderer
			rec := requestWithCSRF(t, e, "/", url.Values{"password": {"synthetic-secret"}, "ttl": {"1"}, "ttlViews": {"1"}})
			if rec.Code != http.StatusOK || renderer.link == "" {
				t.Fatalf("invalid origin did not fall back to long link: status %d", rec.Code)
			}
			requireLongSecretLink(t, renderer.link)
			c, err := redis.Dial("tcp", os.Getenv("OKURU_TEST_REDIS_ADDR"), redis.DialDatabase(12))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			for _, pattern := range []string{"resource_security_short_v2_*"} {
				keys, err := redis.Strings(c.Do("KEYS", pattern))
				if err != nil || len(keys) != 0 {
					t.Fatalf("invalid origin created alias for %s: %v", pattern, err)
				}
			}
		})
	}
}

func TestShortLinkHostHeaderCannotChangeShareOrDeleteLink(t *testing.T) {
	e := shortLinkWebTest(t)
	renderer := &shortLinkCaptureRenderer{}
	e.Renderer = renderer
	page := httptest.NewRecorder()
	e.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "https://attacker.invalid/", nil))
	var cookie *http.Cookie
	for _, c := range page.Result().Cookies() {
		if c.Name == "_csrf" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("missing CSRF cookie")
	}
	values := url.Values{"password": {"synthetic-secret"}, "ttl": {"1"}, "ttlViews": {"1"}, "deletable": {"on"}, "_csrf": {cookie.Value}}
	req := httptest.NewRequest(http.MethodPost, "https://attacker.invalid/", strings.NewReader(values.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("share creation failed: %d", rec.Code)
	}
	requireRootShortLink(t, renderer.link)
	original := shortLinkDestination(t, e, renderer.link)
	if renderer.deleteSecret != "https://share.example.test/remove/"+strings.TrimPrefix(original.Path, "/") {
		t.Fatal("untrusted Host changed secret deletion-link origin or target")
	}
	preview := httptest.NewRecorder()
	e.ServeHTTP(preview, httptest.NewRequest(http.MethodGet, "https://attacker.invalid"+original.Path, nil))
	if preview.Code != http.StatusOK || renderer.previewDelete != renderer.deleteSecret {
		t.Fatal("untrusted Host changed deletion link in the secret preview")
	}
}

func TestShortLinkWebFallbackWhenAliasDatabaseUnavailable(t *testing.T) {
	e := shortLinkWebTest(t)
	t.Setenv("OKURU_SHORTLINK_REDIS_DB", "999") // beyond the disposable server's database count
	renderer := &shortLinkCaptureRenderer{}
	e.Renderer = renderer
	rec := requestWithCSRF(t, e, "/", url.Values{"password": {"synthetic-secret"}, "ttl": {"1"}, "ttlViews": {"1"}, "deletable": {"on"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("share creation should survive alias failure: %d", rec.Code)
	}
	if !strings.HasPrefix(renderer.link, "https://share.example.test/") {
		t.Fatal("missing original-link fallback with trusted origin")
	}
	requireLongSecretLink(t, renderer.link)
	link, err := url.Parse(renderer.link)
	if err != nil {
		t.Fatal(err)
	}
	p := &models.Password{PasswordKey: strings.TrimPrefix(link.Path, "/")}
	if err := u.GetPassword(p); err != nil {
		t.Fatal("original secret was lost on alias-storage failure")
	}
	if renderer.deleteSecret != "https://share.example.test/remove/"+strings.TrimPrefix(link.Path, "/") {
		t.Fatal("alias-storage failure changed deletion-link origin or target")
	}
}

func TestShortLinkProtectedUploadReturnsShortLinks(t *testing.T) {
	for _, mode := range []string{"native", "progress"} {
		t.Run(mode, func(t *testing.T) { testShortLinkProtectedUpload(t, mode == "progress") })
	}
}

func testShortLinkProtectedUpload(t *testing.T, progress bool) {
	e := shortLinkWebTest(t)
	t.Setenv("OKURU_STORAGE_MIN_FREE_BYTES", "1")
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", "268435456")
	t.Setenv("TMPDIR", t.TempDir())
	renderer := &shortLinkCaptureRenderer{}
	e.Renderer = renderer
	page := httptest.NewRecorder()
	e.ServeHTTP(page, httptest.NewRequest(http.MethodGet, "https://attacker.invalid/", nil))
	var cookie *http.Cookie
	for _, c := range page.Result().Cookies() {
		if c.Name == "_csrf" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("missing CSRF cookie")
	}
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("files", "fixture.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.WriteString(part, "synthetic file"); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"_csrf": cookie.Value, "password": "synthetic-file-password", "ttl": "1", "ttlViews": "2", "deletable": "on"} {
		if err := w.WriteField(key, value); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "https://attacker.invalid/file", bytes.NewReader(body.Bytes()))
	req.Header.Set("Content-Type", w.FormDataContentType())
	if progress {
		req.Header.Set("Accept", "application/json")
	}
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload creation failed: status %d", rec.Code)
	}
	if progress {
		var result map[string]string
		if json.Unmarshal(rec.Body.Bytes(), &result) != nil || len(result) != 1 || result["receipt"] == "" ||
			rec.Header().Get("Cache-Control") != "private, no-store" || renderer.fileLink != "" {
			t.Fatal("expected a private receipt response")
		}
		receipt := result["receipt"]
		_, encoded, _ := strings.Cut(receipt, ".")
		payload, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || bytes.Contains(payload, []byte("synthetic-file-password")) {
			t.Fatal("invalid receipt or plaintext archive password in receipt")
		}
		path := "/file/confirmation"
		missingCSRF := httptest.NewRequest(http.MethodPost, path, strings.NewReader(url.Values{"receipt": {receipt}}.Encode()))
		missingCSRF.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		missingCSRF.AddCookie(cookie)
		rejected := httptest.NewRecorder()
		e.ServeHTTP(rejected, missingCSRF)
		if rejected.Code != http.StatusBadRequest {
			t.Fatalf("missing CSRF token: status=%d", rejected.Code)
		}
		if res := requestWithCSRF(t, e, path+"?receipt="+url.QueryEscape(receipt), nil); res.Code != http.StatusNotFound {
			t.Fatalf("accepted receipt from URL: status=%d", res.Code)
		}
		values := url.Values{"receipt": {receipt}}
		var firstFile, firstPassword string
		for i := 0; i < 2; i++ {
			res := requestWithCSRF(t, e, path, values)
			if res.Code != http.StatusOK || res.Header().Get("Cache-Control") != "private, no-store" {
				t.Fatalf("confirmation returned status=%d", res.Code)
			}
			if i != 0 && (renderer.fileLink != firstFile || renderer.passwordLink != firstPassword) {
				t.Fatal("reloading confirmation changed the share links")
			}
			firstFile, firstPassword = renderer.fileLink, renderer.passwordLink
		}
		archives, err := filepath.Glob(filepath.Join(u.FILEFOLDER, "*.zip"))
		if err != nil || len(archives) != 1 {
			t.Fatal("confirming twice did not preserve exactly one archive")
		}
	}
	for _, link := range []string{renderer.fileLink, renderer.passwordLink} {
		requireRootShortLink(t, link)
	}
	fileOriginal := shortLinkDestination(t, e, renderer.fileLink)
	passwordOriginal := shortLinkDestination(t, e, renderer.passwordLink)
	if !strings.HasPrefix(fileOriginal.Path, "/file/") {
		t.Fatal("file alias did not resolve to a file path")
	}
	requireLongSecretLink(t, passwordOriginal.Path)
	fileToken := strings.TrimPrefix(fileOriginal.Path, "/file/")
	conn := u.NewPool().Get()
	defer conn.Close()
	fileID, _, _ := u.ParseToken(fileToken)
	passwordID, _, _ := u.ParseToken(strings.TrimPrefix(passwordOriginal.Path, "/"))
	for _, key := range []string{u.REDIS_PREFIX + "file_" + fileID, u.REDIS_PREFIX + passwordID} {
		if views, err := redis.Int(conn.Do("HGET", key, "views_count")); err != nil || views != 0 {
			t.Fatal("confirmation consumed a view")
		}
	}
	if stored, err := redis.Bool(conn.Do("HEXISTS", u.REDIS_PREFIX+"file_"+fileID, "confirmation_digest")); err != nil || stored != progress {
		t.Fatal("unexpected receipt metadata for the selected upload mode")
	}
	if renderer.deleteFile != "https://share.example.test/file/remove/"+fileToken {
		t.Fatal("untrusted Host changed file deletion-link origin or target")
	}
	preview := httptest.NewRecorder()
	e.ServeHTTP(preview, httptest.NewRequest(http.MethodGet, "https://attacker.invalid"+fileOriginal.Path, nil))
	if preview.Code != http.StatusOK || renderer.previewDelete != renderer.deleteFile {
		t.Fatal("untrusted Host changed deletion link in the file preview")
	}
	wrongValues := url.Values{"_csrf": {cookie.Value}, "password": {""}}
	wrongReq := httptest.NewRequest(http.MethodPost, "https://attacker.invalid"+fileOriginal.Path, strings.NewReader(wrongValues.Encode()))
	wrongReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wrongReq.AddCookie(cookie)
	wrong := httptest.NewRecorder()
	e.ServeHTTP(wrong, wrongReq)
	if wrong.Code != http.StatusUnauthorized || renderer.previewDelete != renderer.deleteFile {
		t.Fatalf("wrong-password response did not retain safe deletion URL: status %d", wrong.Code)
	}
}
