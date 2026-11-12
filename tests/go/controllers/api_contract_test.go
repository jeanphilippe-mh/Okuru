package controllers_test

import (
	"encoding/json"
	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/router"
	u "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
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
	e.ServeHTTP(rec, httptest.NewRequest("GET", "/api/v1", nil))
	token := rec.Header().Get("X-CSRF-Token")
	for _, c := range rec.Result().Cookies() {
		if c.Name == "_csrf" && token != "" {
			return c, token
		}
	}
	t.Fatal("API does not expose a CSRF cookie/header pair")
	return nil, ""
}
func apiRequest(e *echo.Echo, method, path, body, ct string, cookie *http.Cookie, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", ct)
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
	r := apiRequest(e, "POST", "/api/v1", `{"password":"contract-secret","ttl":300,"views":1,"views_count":-100,"token":"client-internal-field"}`, "application/json", cookie, token)
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
	link, err := url.Parse(created["link_api"].(string))
	if err != nil {
		t.Fatal(err)
	}
	r = apiRequest(e, "GET", link.Path, "", "", nil, "")
	var read map[string]interface{}
	if err := json.Unmarshal(r.Body.Bytes(), &read); err != nil {
		t.Fatal(err)
	}
	if r.Code != 200 || read["password"] != "contract-secret" || r.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("read failed: %d %v", r.Code, read)
	}
	r = apiRequest(e, "GET", link.Path, "", "", nil, "")
	if r.Code != 404 || !json.Valid(r.Body.Bytes()) {
		t.Fatalf("repeated read: %d %s", r.Code, r.Body)
	}
}
func TestAPIFormDefaultsAndValidation(t *testing.T) {
	e := apiContractServer(t)
	cookie, token := apiCredentials(t, e)
	r := apiRequest(e, "POST", "/api/v1", url.Values{"password": {"form-secret"}, "_csrf": {token}}.Encode(), "application/x-www-form-urlencoded", cookie, "")
	if r.Code != 201 {
		t.Fatalf("form creation: %d %s", r.Code, r.Body)
	}
	var created map[string]interface{}
	json.Unmarshal(r.Body.Bytes(), &created)
	if created["ttl"] != float64(3600) || created["views"] != float64(1) {
		t.Fatalf("defaults changed: %v", created)
	}
	for _, body := range []string{`{`, `{"password":"test","ttl":-1}`, `{"password":"test","views":101}`, `{"password":"test","ttl":"bad"}`, `{"ttl":300}`} {
		r := apiRequest(e, "POST", "/api/v1", body, "application/json", cookie, token)
		if r.Code != 400 || r.Header().Get("Location") != "" || !json.Valid(r.Body.Bytes()) || strings.Contains(r.Body.String(), "unmarshal") {
			t.Fatalf("invalid input: %d %s", r.Code, r.Body)
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
		r := apiRequest(e, "POST", "/api/v1", `{"password":"not-created"}`, "application/json", pair.cookie, pair.token)
		if r.Code != 400 && r.Code != 403 {
			t.Fatalf("missing/foreign CSRF accepted: %d", r.Code)
		}
		if !json.Valid(r.Body.Bytes()) {
			t.Fatal("CSRF failure not JSON")
		}
	}
}
func TestAPIRejectsFileNamespaceBeforeDisclosure(t *testing.T) {
	e := apiContractServer(t)
	token, err := u.SetFile("additional-password", 300, 2, true, true, "")
	if err != nil {
		t.Fatal(err)
	}
	r := apiRequest(e, "GET", "/api/v1/file_"+token, "", "", nil, "")
	if r.Code != 404 || strings.Contains(r.Body.String(), "additional-password") {
		t.Fatalf("file password disclosed: %d", r.Code)
	}
}
