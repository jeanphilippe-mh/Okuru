package router

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeanphilippe-mh/Okuru/routes"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

// Route registration and preprocessing match the production router. The two
// share handlers are replaced only to observe routing and token validation
// without Redis, state consumption, templates, or real secrets.
func TestShareRoutesKeepTokensWithTrailingSlash(t *testing.T) {
	e := echo.New()
	e.Pre(middleware.RemoveTrailingSlash())
	routes.Index(e)
	routes.File(e.Group("/file"))
	_, key, err := utils.Encrypt("synthetic fixture")
	if err != nil {
		t.Fatal(err)
	}
	token := "b98a99b6-88fe-4fc7-a627-b6e6e009d31d" + utils.TOKEN_SEPARATOR + key
	called := ""
	observe := func(kind, param string) echo.HandlerFunc {
		return func(c echo.Context) error {
			called = kind
			id, decodedKey, err := utils.ParseToken(c.Param(param))
			if err != nil || id != "b98a99b6-88fe-4fc7-a627-b6e6e009d31d" || decodedKey != key {
				return c.NoContent(http.StatusBadRequest)
			}
			return c.NoContent(http.StatusNoContent)
		}
	}
	e.GET("/:password_key", observe("secret", "password_key"))
	e.GET("/file/:file_key", observe("file", "file_key"))
	for _, tc := range []struct{ name, path, want string }{
		{"secret", "/" + token, "secret"},
		{"secret-slash-query", "/" + token + "/?source=test", "secret"},
		{"file", "/file/" + token, "file"},
		{"file-slash-query", "/file/" + token + "/?source=test", "file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called = ""
			w := httptest.NewRecorder()
			e.ServeHTTP(w, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if w.Code != http.StatusNoContent || called != tc.want {
				t.Fatalf("status=%d handler=%q", w.Code, called)
			}
		})
	}
	for _, path := range []string{
		"/file/b98a99b6-88fe-4fc7-a627-b6e6e009d31d%2Fother" + utils.TOKEN_SEPARATOR + key + "/",
		"/b98a99b6-88fe-4fc7-a627-b6e6e009d31d%2Fother" + utils.TOKEN_SEPARATOR + key + "/",
	} {
		called = ""
		w := httptest.NewRecorder()
		e.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if w.Code == http.StatusNoContent {
			t.Fatalf("escaped slash changed into an accepted token: %s", path)
		}
	}
}

func TestRemoveTrailingSlashPreservesEscapedSlash(t *testing.T) {
	e := echo.New()
	e.Pre(middleware.RemoveTrailingSlash())
	e.GET("/escape/*", func(c echo.Context) error {
		r := c.Request()
		if r.RequestURI != "/escape/part%2Fpart?x=1" || r.URL.RawPath != "/escape/part%2Fpart" {
			t.Fatalf("encoded path was changed: requestURI=%q rawPath=%q", r.RequestURI, r.URL.RawPath)
		}
		if !strings.Contains(c.Param("*"), "%2F") {
			t.Fatalf("router lost escaped separator: %q", c.Param("*"))
		}
		return c.NoContent(http.StatusNoContent)
	})
	w := httptest.NewRecorder()
	e.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/escape/part%2Fpart/?x=1", nil))
	if w.Code != http.StatusNoContent {
		t.Fatalf("escaped route returned %d", w.Code)
	}
}
