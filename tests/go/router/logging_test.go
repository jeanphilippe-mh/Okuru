package router

import (
	"errors"
	"github.com/labstack/echo/v4"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSensitiveURLsAreNotLogged(t *testing.T) {
	e := echo.New()
	e.GET("/:password_key", func(c echo.Context) error {
		route := safeLogRoute(c)
		if route != "/:password_key" || strings.Contains(route, "secret-key") {
			t.Fatalf("unsafe route %q", route)
		}
		return c.NoContent(204)
	})
	e.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/uuid~secret-key?password=private", nil))
	c := e.NewContext(httptest.NewRequest("GET", "/unknown~secret-key", nil), httptest.NewRecorder())
	if safeLogRoute(c) != "unmatched" {
		t.Fatal("unmatched path logged")
	}
	if safeLogError(errors.New("failure at /uuid~secret-key")) != "request failed" {
		t.Fatal("raw error logged")
	}
	if safeLogError(echo.NewHTTPError(400, "private-payload")) != "Bad Request" {
		t.Fatal("HTTP error body logged")
	}
}
