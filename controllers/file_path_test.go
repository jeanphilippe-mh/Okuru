package controllers

import (
	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestArchiveNameFromToken(t *testing.T) {
	id := "123e4567-e89b-42d3-a456-426614174000"
	name, err := archiveNameFromToken(id + TOKEN_SEPARATOR + "key")
	if err != nil || name != id+".zip" {
		t.Fatalf("valid identifier: %q, %v", name, err)
	}
	for _, key := range []string{"", "..", "../" + id, "/" + id, `..\` + id, "%2e%2e%2f" + id, id + "/other", id + "\x00", "123E4567-e89b-42d3-a456-426614174000", "urn:uuid:" + id, "{" + id + "}", "123e4567e89b42d3a456426614174000"} {
		if name, err := archiveNameFromToken(key + TOKEN_SEPARATOR + "key"); err == nil || name != "" {
			t.Errorf("accepted %q", key)
		}
	}
	for _, token := range []string{id, id + TOKEN_SEPARATOR, id + TOKEN_SEPARATOR + "key" + TOKEN_SEPARATOR + "extra"} {
		if _, err := archiveNameFromToken(token); err == nil {
			t.Errorf("accepted malformed token %q", token)
		}
	}
}

func TestDownloadRejectsInvalidPathBeforeStorage(t *testing.T) {
	e := echo.New()
	req := httptest.NewRequest(http.MethodPost, "/download", nil)
	response := httptest.NewRecorder()
	c := e.NewContext(req, response)
	c.SetParamNames("file_key")
	c.SetParamValues("../outside" + TOKEN_SEPARATOR + "key")
	if err := DownloadFile(c); err != nil {
		t.Fatal(err)
	}
	if response.Code != http.StatusNotFound {
		t.Fatalf("status = %d", response.Code)
	}
}
