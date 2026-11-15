package controllers_test

import (
	"bytes"
	"context"
	"encoding/base64"
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
	"github.com/labstack/echo/v4"
)

type shortLinkCaptureRenderer struct {
	link             string
	original         string
	fileLink         string
	originalFile     string
	passwordLink     string
	originalPassword string
	deleteSecret     string
	deleteFile       string
	previewDelete    string
}

func (r *shortLinkCaptureRenderer) Render(w io.Writer, name string, data interface{}, _ echo.Context) error {
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
		r.original, _ = values["originalLink"].(string)
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
		r.originalFile, _ = values["originalFileLink"].(string)
		r.passwordLink, _ = values["passwordLink"].(string)
		r.originalPassword, _ = values["originalPasswordLink"].(string)
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

func shortLinkWebTest(t *testing.T) *echo.Echo {
	t.Helper()
	e := resourceTest(t)
	t.Setenv("OKURU_SHORTLINK_REDIS_DB", "12")
	t.Setenv("OKURU_SHORTLINK_PUBLIC_ORIGIN", "https://share.example.test")
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	t.Cleanup(func() {
		c, err := redis.Dial("tcp", addr, redis.DialDatabase(12))
		if err == nil {
			defer c.Close()
			keys, _ := redis.Strings(c.Do("KEYS", "resource_security_short_v1_*"))
			for _, key := range keys {
				_, _ = c.Do("DEL", key)
			}
		}
		_ = u.CloseShortLinkPool()
	})
	return e
}

// A root short URL is exactly one canonical, unpadded base64url encoding of
// 32 random bytes. Checking the whole shape distinguishes it from long links.
func requireRootShortLink(t *testing.T, link string) *url.URL {
	t.Helper()
	u, err := url.Parse(link)
	if err != nil || u.Scheme != "https" || u.Host != "share.example.test" || u.RawQuery != "" || u.Fragment != "" {
		t.Fatal("short URL has an unexpected origin or query")
	}
	alias := strings.TrimPrefix(u.Path, "/")
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(alias)
	if u.Path != "/"+alias || len(alias) != 43 || err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != alias {
		t.Fatal("short URL is not a canonical 256-bit alias at the root")
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

func TestShortLinkWebSecretRoundTripAndViews(t *testing.T) {
	e := shortLinkWebTest(t)
	renderer := &shortLinkCaptureRenderer{}
	e.Renderer = renderer
	created := requestWithCSRF(t, e, "/", url.Values{"password": {"synthetic-secret"}, "ttl": {"1"}, "ttlViews": {"2"}})
	if created.Code != http.StatusOK {
		t.Fatalf("share creation failed: status %d", created.Code)
	}
	shortURL := requireRootShortLink(t, renderer.link)
	if renderer.original == "" || renderer.original == renderer.link {
		t.Fatal("original long URL not retained for recovery")
	}
	longURL, err := url.Parse(renderer.original)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.TrimPrefix(longURL.Path, "/")
	requireLongSecretLink(t, renderer.original)
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
	token, err := u.SetFile("sample-file-password", 120, 1, true, false, "")
	if err != nil {
		t.Fatal(err)
	}
	id, _, parseErr := u.ParseToken(token)
	if parseErr != nil {
		t.Fatal(parseErr)
	}
	if err := os.WriteFile(filepath.Join(u.FILEFOLDER, id+".zip"), []byte("file-content"), 0600); err != nil {
		t.Fatal(err)
	}
	alias, createErr := u.CreateShortLink(context.Background(), token, true)
	if createErr != nil {
		t.Fatal(createErr)
	}
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(method, "/"+alias, nil))
		if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/file/"+token {
			t.Fatalf("file %s redirect failed: %d", method, rec.Code)
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
	encoded := fmt.Sprintf("/%%%02X%s", alias[0], alias[1:])
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		for _, path := range []string{"/" + alias, "/" + alias + "/", encoded} {
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
		e.ServeHTTP(legacy, httptest.NewRequest(method, "/s/"+alias, nil))
		if legacy.Code >= 300 && legacy.Code < 400 || legacy.Header().Get("Location") == "/"+token {
			t.Fatalf("removed /s/ route resolved on %s: status=%d", method, legacy.Code)
		}
	}
	// Ordinary named routes must still resolve through their original handler.
	privacy := httptest.NewRecorder()
	e.ServeHTTP(privacy, httptest.NewRequest(http.MethodGet, "/privacy-policy", nil))
	if privacy.Code != http.StatusOK {
		t.Fatalf("named route changed behavior: status=%d", privacy.Code)
	}
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
	unknown := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	for _, method := range []string{http.MethodGet, http.MethodHead} {
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(method, "/"+unknown, nil))
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "static fallback sentinel") {
			t.Fatalf("static HTML5 fallback intercepted %s unknown alias: status=%d", method, rec.Code)
		}
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
			t.Fatalf("static middleware caused missing privacy headers for %s", method)
		}
	}
}

func TestShortLinkWebPrivacyHeadersOnFailure(t *testing.T) {
	e := shortLinkWebTest(t)
	unknown := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	noncanonical := strings.Repeat("A", 42) + "B"
	for _, tc := range []struct{ method, path string }{
		{http.MethodGet, "/" + unknown}, {http.MethodHead, "/" + unknown},
		{http.MethodPost, "/" + unknown}, {http.MethodGet, "/" + noncanonical},
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
			if renderer.original != "" {
				t.Fatal("fallback is already the original link")
			}
			c, err := redis.Dial("tcp", os.Getenv("OKURU_TEST_REDIS_ADDR"), redis.DialDatabase(12))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			keys, err := redis.Strings(c.Do("KEYS", "resource_security_short_v1_*"))
			if err != nil || len(keys) != 0 {
				t.Fatalf("invalid origin created alias: %v", err)
			}
		})
	}
}

func TestShortLinkHostHeaderCannotChangeShortOrOriginalLink(t *testing.T) {
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
	if !strings.HasPrefix(renderer.original, "https://share.example.test/") || strings.Contains(renderer.original, "attacker.invalid") {
		t.Fatal("untrusted Host changed original-link origin")
	}
	original, err := url.Parse(renderer.original)
	if err != nil {
		t.Fatal(err)
	}
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

func TestShortLinkProtectedUploadReturnsBothShortAndOriginalLinks(t *testing.T) {
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
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload creation failed: status %d", rec.Code)
	}
	for _, link := range []string{renderer.fileLink, renderer.passwordLink} {
		requireRootShortLink(t, link)
	}
	for _, link := range []string{renderer.originalFile, renderer.originalPassword} {
		if !strings.HasPrefix(link, "https://share.example.test/") || strings.Contains(link, "attacker.invalid") {
			t.Fatal("protected upload lost the trusted original links")
		}
	}
	fileOriginal, err := url.Parse(renderer.originalFile)
	if err != nil {
		t.Fatal(err)
	}
	fileToken := strings.TrimPrefix(fileOriginal.Path, "/file/")
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
	for _, pair := range [][2]string{{renderer.fileLink, renderer.originalFile}, {renderer.passwordLink, renderer.originalPassword}} {
		short, _ := url.Parse(pair[0])
		original, _ := url.Parse(pair[1])
		out := httptest.NewRecorder()
		e.ServeHTTP(out, httptest.NewRequest(http.MethodGet, short.Path, nil))
		if out.Code != http.StatusFound || out.Header().Get("Location") != original.Path {
			t.Fatal("protected upload alias did not resolve to its original path")
		}
	}
}
