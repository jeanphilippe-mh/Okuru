package controllers_test

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/controllers"
	"github.com/jeanphilippe-mh/Okuru/models"
	"github.com/jeanphilippe-mh/Okuru/router"
	u "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
)

type securityRenderer struct{}

func (securityRenderer) Render(w io.Writer, _ string, _ interface{}, _ echo.Context) error {
	_, err := io.WriteString(w, "test page")
	return err
}
func resourceTest(t *testing.T) *echo.Echo {
	t.Helper()
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("isolated Redis required")
	}
	h, p, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	oh, op, odb, opass, opre, of := u.REDIS_HOST, u.REDIS_PORT, u.REDIS_DB, u.REDIS_PASSWORD, u.REDIS_PREFIX, u.FILEFOLDER
	u.REDIS_HOST, u.REDIS_PORT, u.REDIS_DB, u.REDIS_PASSWORD, u.REDIS_PREFIX, u.FILEFOLDER = h, p, "0", "", "resource_security_", t.TempDir()
	t.Cleanup(func() {
		c, e := redis.Dial("tcp", addr)
		if e == nil {
			defer c.Close()
			keys, _ := redis.Strings(c.Do("KEYS", "resource_security_*"))
			for _, k := range keys {
				c.Do("DEL", k)
			}
		}
		u.REDIS_HOST, u.REDIS_PORT, u.REDIS_DB, u.REDIS_PASSWORD, u.REDIS_PREFIX, u.FILEFOLDER = oh, op, odb, opass, opre, of
	})
	e := router.New()
	e.Renderer = securityRenderer{}
	router.ConfigureErrorHandler(e, t.TempDir())
	return e
}
func requestWithCSRF(t *testing.T, e *echo.Echo, path string, fields url.Values) *httptest.ResponseRecorder {
	t.Helper()
	page := httptest.NewRecorder()
	e.ServeHTTP(page, httptest.NewRequest("GET", "/", nil))
	var cookie *http.Cookie
	for _, c := range page.Result().Cookies() {
		if c.Name == "_csrf" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("missing CSRF cookie")
	}
	if fields == nil {
		fields = url.Values{}
	}
	fields.Set("_csrf", cookie.Value)
	req := httptest.NewRequest("POST", path, strings.NewReader(fields.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}
func TestFileTokensCannotBeUsedAsSecretTokens(t *testing.T) {
	e := resourceTest(t)
	token, err := u.SetFile("additional-password", 300, 3, true, true, "")
	if err != nil {
		t.Fatal(err)
	}
	id, key, _ := u.ParseToken(token)
	path := filepath.Join(u.FILEFOLDER, id+".zip")
	if err := os.WriteFile(path, []byte("owned-archive"), 0600); err != nil {
		t.Fatal(err)
	}
	altered := "file_" + id + u.TOKEN_SEPARATOR + key
	rec := requestWithCSRF(t, e, "/"+altered, nil)
	if rec.Code != 404 || strings.Contains(rec.Body.String(), "additional-password") {
		t.Fatalf("secret route accepted file token: %d", rec.Code)
	}
	for _, handler := range []echo.HandlerFunc{controllers.ReadIndex, controllers.ReadPassword, controllers.DeleteIndex} {
		rec := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest("GET", "/", nil), rec)
		c.SetParamNames("password_key")
		c.SetParamValues(altered)
		if err := handler(c); err != nil {
			e.HTTPErrorHandler(err, c)
		}
		if strings.Contains(rec.Body.String(), "additional-password") {
			t.Fatal("file password disclosed")
		}
	}
	f := &models.File{FileKey: token}
	if err := u.GetFile(f); err != nil || f.Views != 3 {
		t.Fatalf("rejected cross-resource access changed file views: %v", err)
	}
	denied := requestWithCSRF(t, e, "/file/"+token, url.Values{"password": {"wrong-password"}})
	if denied.Code != 401 {
		t.Fatalf("wrong password status=%d", denied.Code)
	}
	dl := requestWithCSRF(t, e, "/file/"+token, url.Values{"password": {"additional-password"}})
	if dl.Code != 200 || dl.Body.String() != "owned-archive" {
		t.Fatalf("valid download broken: %d", dl.Code)
	}
}
func TestDeletionAuthenticatesKeyAndPreservesAttempts(t *testing.T) {
	resourceTest(t)
	for _, file := range []bool{false, true} {
		for _, deletable := range []bool{false, true} {
			var token string
			var err *echo.HTTPError
			if file {
				token, err = u.SetFile("test-password", 300, 3, deletable, false, "")
			} else {
				token, err = u.SetPassword("test-secret", 300, 3, deletable)
			}
			if err != nil {
				t.Fatal(err)
			}
			id, _, _ := u.ParseToken(token)
			var archive string
			if file {
				archive = filepath.Join(u.FILEFOLDER, id+".zip")
				if err := os.WriteFile(archive, []byte("owned"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			remove := func(key string) *echo.HTTPError {
				if file {
					return u.RemoveFile(&models.File{FileKey: key})
				}
				return u.RemovePassword(&models.Password{PasswordKey: key})
			}
			for _, wrong := range []string{id + u.TOKEN_SEPARATOR + "wrong", id + u.TOKEN_SEPARATOR} {
				if err := remove(wrong); err == nil || err.Code != 404 {
					t.Fatalf("invalid deletion accepted: %v", err)
				}
			}
			if file {
				f := &models.File{FileKey: token}
				if err := u.GetFile(f); err != nil || f.Views != 3 {
					t.Fatalf("file changed after invalid deletion: %v", err)
				}
				if _, err := os.Stat(archive); err != nil {
					t.Fatal(err)
				}
			} else {
				p := &models.Password{PasswordKey: token}
				if err := u.GetPassword(p); err != nil || p.Views != 3 {
					t.Fatalf("secret changed after invalid deletion: %v", err)
				}
			}
			err = remove(token)
			if deletable {
				if err != nil {
					t.Fatal(err)
				}
				if file {
					if _, err := os.Stat(archive); !os.IsNotExist(err) {
						t.Fatal("archive not removed")
					}
				}
			} else if err == nil || err.Code != 401 {
				t.Fatalf("non-deletable resource removed: %v", err)
			}
		}
	}
}
func TestLegacyCanonicalTokensStillWork(t *testing.T) {
	e := resourceTest(t)
	token, err := u.SetPassword("legacy-format-secret", 300, 1, true)
	if err != nil {
		t.Fatal(err)
	}
	p := &models.Password{PasswordKey: token}
	if err := u.GetPassword(p); err != nil || p.Password != "" || p.Views != 1 {
		t.Fatalf("preview changed: %v", err)
	}
	r := requestWithCSRF(t, e, "/"+token, nil)
	if r.Code != 200 || r.Body.String() != "legacy-format-secret" {
		t.Fatalf("legacy token rejected: %d", r.Code)
	}
	r = requestWithCSRF(t, e, "/"+token, nil)
	if r.Code != 404 {
		t.Fatalf("single-use token reusable: %d", r.Code)
	}
}

func TestDeletionLinksAreReadOnlyUntilCSRFProtectedConfirmation(t *testing.T) {
	e := resourceTest(t)
	for _, file := range []bool{false, true} {
		var token string
		var err *echo.HTTPError
		if file {
			token, err = u.SetFile("test-password", 300, 1, true, false, "")
		} else {
			token, err = u.SetPassword("test-secret", 300, 1, true)
		}
		if err != nil {
			t.Fatal(err)
		}
		path := "/remove/" + token
		if file {
			path = "/file/remove/" + token
			id, _, _ := u.ParseToken(token)
			os.WriteFile(filepath.Join(u.FILEFOLDER, id+".zip"), []byte("owned"), 0600)
			if err := u.RetrieveFilePassword(&models.File{FileKey: token}); err != nil {
				t.Fatal(err)
			}
		}
		// Even an exhausted archive remains deletable without reopening a download.
		get := httptest.NewRecorder()
		e.ServeHTTP(get, httptest.NewRequest("GET", path, nil))
		if get.Code != 200 {
			t.Fatalf("confirmation status=%d", get.Code)
		}
		if file {
			if err := u.GetFileForDeletion(&models.File{FileKey: token}); err != nil {
				t.Fatal("GET deleted archive")
			}
		} else {
			if err := u.GetPassword(&models.Password{PasswordKey: token}); err != nil {
				t.Fatal("GET deleted secret")
			}
		}
		noCSRF := httptest.NewRecorder()
		e.ServeHTTP(noCSRF, httptest.NewRequest("POST", path, nil))
		if noCSRF.Code != 400 && noCSRF.Code != 403 {
			t.Fatalf("deletion missing CSRF accepted: %d", noCSRF.Code)
		}
		post := requestWithCSRF(t, e, path, nil)
		if post.Code != 200 {
			t.Fatalf("confirmed deletion failed: %d", post.Code)
		}
		if file {
			if err := u.GetFileForDeletion(&models.File{FileKey: token}); err == nil {
				t.Fatal("archive retained")
			}
		} else {
			if err := u.GetPassword(&models.Password{PasswordKey: token}); err == nil {
				t.Fatal("secret retained")
			}
		}
	}
}
