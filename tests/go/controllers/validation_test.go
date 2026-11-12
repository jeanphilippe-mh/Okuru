package controllers

import (
	"github.com/labstack/echo/v4"
	"io"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type testRenderer struct{}

func (testRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	_, err := io.WriteString(w, "invalid input")
	return err
}

func TestInvalidWebParametersAreRejectedBeforeStorage(t *testing.T) {
	for _, handler := range []echo.HandlerFunc{AddIndex, AddFile} {
		for _, fields := range []url.Values{
			{"ttl": {"-1"}, "ttlViews": {"1"}},
			{"ttl": {"1"}, "ttlViews": {"0"}},
			{"ttl": {"1"}, "ttlViews": {"101"}},
			{"ttl": {"invalid"}, "ttlViews": {"1"}},
		} {
			e := echo.New()
			e.Renderer = testRenderer{}
			req := httptest.NewRequest("POST", "/", strings.NewReader(fields.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			response := httptest.NewRecorder()
			if err := handler(e.NewContext(req, response)); err != nil {
				t.Fatal(err)
			}
			if response.Code != 400 {
				t.Fatalf("invalid input accepted: %v code=%d", fields, response.Code)
			}
		}
	}
}
