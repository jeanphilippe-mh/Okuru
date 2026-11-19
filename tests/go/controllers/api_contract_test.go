package controllers_test

import (
	"encoding/json"
	"fmt"
	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/router"
	u "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func apiContractServer(t *testing.T) *echo.Echo {
	t.Helper()
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("isolated Redis required")
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	oh, op, odb, opass, opre := u.REDIS_HOST, u.REDIS_PORT, u.REDIS_DB, u.REDIS_PASSWORD, u.REDIS_PREFIX
	u.REDIS_HOST, u.REDIS_PORT, u.REDIS_DB, u.REDIS_PASSWORD, u.REDIS_PREFIX = h, p, "0", "", "api_contract_"
	t.Cleanup(func() {
		c, e := redis.Dial("tcp", addr)
		if e == nil {
			defer c.Close()
			keys, _ := redis.Strings(c.Do("KEYS", "api_contract_*"))
			for _, k := range keys {
				c.Do("DEL", k)
			}
		}
		u.REDIS_HOST, u.REDIS_PORT, u.REDIS_DB, u.REDIS_PASSWORD, u.REDIS_PREFIX = oh, op, odb, opass, opre
	})
	e := router.New()
	router.ConfigureErrorHandler(e, t.TempDir())
	return e
}
func apiCredentials(t *testing.T, e *echo.Echo) (*http.Cookie, string) {
	t.Helper()
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v2/secrets/bootstrap", nil))
	token := rec.Header().Get("X-CSRF-Token")
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__Host-okuru-secret-csrf" && token != "" {
			if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || c.Value != token {
				t.Fatal("invalid v2 CSRF cookie")
			}
			return c, token
		}
	}
	t.Fatal("API does not expose a CSRF cookie/header pair")
	return nil, ""
}
func apiRequest(e *echo.Echo, method, path, body, ct string, cookie *http.Cookie, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", ct)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if cookie != nil {
		req.AddCookie(cookie)
	}
	if token != "" {
		req.Header.Set("X-CSRF-Token", token)
	}
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}
func TestAPIJSONCreateReadAndSingleUse(t *testing.T) {
	e := apiContractServer(t)
	cookie, token := apiCredentials(t, e)
	r := apiRequest(e, "POST", "/api/v2/secrets", `{"password":"contract-secret","ttl_seconds":300,"views":1}`, "application/json", cookie, token)
	if r.Code != 201 {
		t.Fatalf("JSON creation: %d %s", r.Code, r.Body)
	}
	var created map[string]interface{}
	if err := json.Unmarshal(r.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if _, ok := created["password"]; ok {
		t.Fatal("creation leaked password")
	}
	link, err := url.Parse(created["api_link"].(string))
	if err != nil {
		t.Fatal(err)
	}
	r = apiRequest(e, "GET", link.Path, "", "", nil, "")
	var read map[string]interface{}
	if err := json.Unmarshal(r.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	if r.Code != 200 || read["password"] != "contract-secret" || !strings.Contains(r.Header().Get("Cache-Control"), "no-store") {
		t.Fatalf("read failed: %d %v", r.Code, read)
	}
	r = apiRequest(e, "GET", link.Path, "", "", nil, "")
	if r.Code != 404 || !json.Valid(r.Body.Bytes()) {
		t.Fatalf("repeated read: %d %s", r.Code, r.Body)
	}
}

func TestAPISecretCreationCapacityReturns503(t *testing.T) {
	e := apiContractServer(t)
	t.Setenv("OKURU_REDIS_SECRET_MAX_KEYS", "1")
	cookie, token := apiCredentials(t, e)
	r := apiRequest(e, "POST", "/api/v2/secrets", `{"password":"contract-secret","ttl_seconds":300,"views":1}`, "application/json", cookie, token)
	if r.Code != http.StatusServiceUnavailable {
		t.Fatalf("capacity refusal should be 503, got %d %s", r.Code, r.Body)
	}
}

func TestWebSecretCreationCapacityReturns503(t *testing.T) {
	e := resourceTest(t)
	t.Setenv("OKURU_REDIS_SECRET_MAX_KEYS", "1")
	r := requestWithCSRF(t, e, "/", url.Values{
		"password": {"contract-secret"},
		"ttl":      {"1"},
		"ttlViews": {"1"},
	})
	if r.Code != http.StatusServiceUnavailable {
		t.Fatalf("capacity refusal should be 503, got %d %s", r.Code, r.Body)
	}
}

func TestWebAndAPICreationSharePerOriginBudget(t *testing.T) {
	e := apiContractServer(t)
	e.Renderer = securityRenderer{}
	cookie, token := apiCredentials(t, e)
	for i := 0; i < 49; i++ {
		r := apiRequest(e, "POST", "/api/v2/secrets", `{"password":"contract-secret","ttl_seconds":300,"views":1}`, "application/json", cookie, token)
		if r.Code != http.StatusCreated {
			t.Fatalf("API creation %d failed: %d %s", i, r.Code, r.Body)
		}
	}
	web := requestWithCSRF(t, e, "/", url.Values{
		"password": {"contract-secret"},
		"ttl":      {"1"},
		"ttlViews": {"1"},
	})
	if web.Code != http.StatusOK {
		t.Fatalf("web creation did not share the allowed budget: %d %s", web.Code, web.Body)
	}
	limited := apiRequest(e, "POST", "/api/v2/secrets", `{"password":"contract-secret","ttl_seconds":300,"views":1}`, "application/json", cookie, token)
	if limited.Code != http.StatusTooManyRequests {
		t.Fatalf("shared origin budget did not reject request: %d %s", limited.Code, limited.Body)
	}
}

func TestUntrustedLoopbackProxyDoesNotApplySmallSharedOriginBudget(t *testing.T) {
	e := apiContractServer(t)
	t.Setenv("OKURU_TRUSTED_PROXY_CIDRS", "")
	cookie, token := apiCredentials(t, e)
	for i := 0; i < 51; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/v2/secrets", strings.NewReader(`{"password":"contract-secret","ttl_seconds":300,"views":1}`))
		req.RemoteAddr = "127.0.0.1:43100"
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-CSRF-Token", token)
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i+1))
		req.AddCookie(cookie)
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, req)
		if rec.Code != http.StatusCreated {
			t.Fatalf("loopback proxy hit the smaller per-origin limit at request %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	conn, err := redis.Dial("tcp", os.Getenv("OKURU_TEST_REDIS_ADDR"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	keys, err := redis.Strings(conn.Do("KEYS", "api_contract_admission_secret_create_*"))
	if err != nil || len(keys) != 2 {
		t.Fatalf("untrusted forwarding header unexpectedly split identities: %d keys, %v", len(keys), err)
	}
}
func TestAPIJSONDefaultsAndValidation(t *testing.T) {
	e := apiContractServer(t)
	cookie, token := apiCredentials(t, e)
	encoded := url.Values{"password": {"form-secret"}, "_csrf": {token}}.Encode()
	if r := apiRequest(e, "POST", "/api/v2/secrets", encoded, "application/x-www-form-urlencoded", cookie, token); r.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("form submission returned %d", r.Code)
	}
	r := apiRequest(e, "POST", "/api/v2/secrets", `{"password":"default-settings"}`, "application/json", cookie, token)
	var created map[string]interface{}
	if err := json.Unmarshal(r.Body.Bytes(), &created); err != nil || r.Code != 201 || created["ttl_seconds"] != float64(3600) || created["views"] != float64(1) {
		t.Fatalf("JSON creation did not apply defaults: status=%d err=%v", r.Code, err)
	}
	for _, body := range []string{`{`, `{"password":"test","ttl_seconds":-1}`, `{"password":"test","views":101}`, `{"password":"test","ttl_seconds":"bad"}`,
		`{"ttl_seconds":300}`, `{"password":"test","ttl":300}`, `{"password":"test","views_count":-100}`, `{"password":"test","token":"internal"}`,
		`{"password":"one","password":"two"}`, `{"password":"test","views":0}`, `{"password":"test","views":null}`, `{"Password":"test"}`, `{"password":"test"}{}`} {
		r := apiRequest(e, "POST", "/api/v2/secrets", body, "application/json", cookie, token)
		var failure struct{ Code, Message string }
		if err := json.Unmarshal(r.Body.Bytes(), &failure); err != nil || r.Code != 400 || failure.Code == "" || failure.Message == "" ||
			r.Header().Get("Location") != "" || strings.Contains(r.Body.String(), "unmarshal") {
			t.Fatalf("invalid input did not return a safe structured 400: status=%d", r.Code)
		}
	}
}
func TestAPIHeaderDoesNotDisableCSRF(t *testing.T) {
	e := apiContractServer(t)
	cookie, token := apiCredentials(t, e)
	foreign, other := apiCredentials(t, e)
	_ = foreign
	for _, pair := range []struct {
		cookie *http.Cookie
		token  string
	}{{cookie, ""}, {cookie, other}, {nil, token}} {
		r := apiRequest(e, "POST", "/api/v2/secrets", `{"password":"not-created"}`, "application/json", pair.cookie, pair.token)
		if r.Code != 403 {
			t.Fatalf("missing/foreign CSRF accepted: %d", r.Code)
		}
		if !json.Valid(r.Body.Bytes()) {
			t.Fatal("CSRF failure not JSON")
		}
	}
}
func TestAPIRejectsFileNamespaceBeforeDisclosure(t *testing.T) {
	e := apiContractServer(t)
	token, err := u.SetFile("additional-password", 300, 2, true, true, resourcePasswordID(t, "additional-password"), u.ArchiveFormatAgeUserPassword)
	if err != nil {
		t.Fatal(err)
	}
	r := apiRequest(e, "GET", "/api/v2/secrets/file_"+token, "", "", nil, "")
	if r.Code != 404 || strings.Contains(r.Body.String(), "additional-password") {
		t.Fatalf("file password disclosed: %d", r.Code)
	}
}

func TestSecretAPIProtectedDeletionAndRetiredRoutes(t *testing.T) {
	e := apiContractServer(t)
	cookie, csrf := apiCredentials(t, e)
	for _, endpoint := range []string{"/api/v1", "/api/v1/arbitrary"} {
		r := apiRequest(e, http.MethodGet, endpoint, "", "", nil, "")
		if r.Code != http.StatusNotFound {
			t.Fatalf("retired endpoint returned %d", r.Code)
		}
	}
	create := func(body string) string {
		t.Helper()
		r := apiRequest(e, http.MethodPost, "/api/v2/secrets", body, "application/json", cookie, csrf)
		var share struct {
			API string `json:"api_link"`
		}
		if err := json.Unmarshal(r.Body.Bytes(), &share); r.Code != http.StatusCreated || err != nil {
			t.Fatalf("could not create test secret, status=%d", r.Code)
		}
		link, err := url.Parse(share.API)
		if err != nil || !strings.HasPrefix(link.Path, "/api/v2/secrets/") {
			t.Fatal("missing public API link")
		}
		return link.Path
	}
	path := create(`{"password":"removable","deletable":true}`)
	if r := apiRequest(e, http.MethodDelete, path, "", "", cookie, ""); r.Code != http.StatusForbidden {
		t.Fatalf("delete without header returned %d", r.Code)
	}
	if r := apiRequest(e, http.MethodDelete, path+"invalid", "", "", cookie, csrf); r.Code != http.StatusNotFound {
		t.Fatalf("delete with wrong capability returned %d", r.Code)
	}
	if r := apiRequest(e, http.MethodDelete, path, "", "", cookie, csrf); r.Code != http.StatusNoContent {
		t.Fatalf("authenticated deletion returned %d", r.Code)
	}
	if r := apiRequest(e, http.MethodGet, path, "", "", nil, ""); r.Code != http.StatusNotFound {
		t.Fatalf("deleted secret returned %d", r.Code)
	}
	fixed := create(`{"password":"keep"}`)
	if r := apiRequest(e, http.MethodDelete, fixed, "", "", cookie, csrf); r.Code != http.StatusForbidden {
		t.Fatalf("non-deletable secret returned %d", r.Code)
	}
	if r := apiRequest(e, http.MethodGet, fixed, "", "", nil, ""); r.Code != http.StatusOK {
		t.Fatalf("refused deletion damaged the secret: status %d", r.Code)
	}
}
