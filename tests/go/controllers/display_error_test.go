package controllers

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestValidationMessagesBeginWithCapitalLetter(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ttl   string
		views string
		want  string
	}{
		{"duration", "0", "1", "Duration must be between 1 and 30"},
		{"attempts", "1", "0", "Attempts must be between 1 and 100"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := echo.New()
			e.Renderer = errorMessageRenderer{}
			fields := url.Values{"ttl": {tc.ttl}, "ttlViews": {tc.views}}
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(fields.Encode()))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
			rec := httptest.NewRecorder()
			if err := AddIndex(e.NewContext(req, rec)); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.want) || rec.Header().Get("Refresh") != "3; url=/" {
				t.Fatalf("status %d, response %q; want %q", rec.Code, rec.Body.String(), tc.want)
			}
		})
	}
}

func TestUploadErrorBeginsWithCapitalLetter(t *testing.T) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	if err := w.WriteField("ttl", "1"); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteField("ttlViews", "1"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	e.Renderer = errorMessageRenderer{}
	e.Validator = uploadValidator{}
	req := httptest.NewRequest(http.MethodPost, "/file", &body)
	req.Header.Set(echo.HeaderContentType, w.FormDataContentType())
	rec := httptest.NewRecorder()
	if err := AddFile(e.NewContext(req, rec)); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "No files selected") ||
		rec.Header().Get("Refresh") != "3; url=/file" {
		t.Fatalf("status %d, response %q", rec.Code, rec.Body.String())
	}
}

func TestInvalidFilenameUsesFileFormReturnOnlyForHTML(t *testing.T) {
	e := echo.New()
	e.Renderer = errorMessageRenderer{}
	e.Validator = uploadValidator{}
	for _, accept := range []string{echo.MIMETextHTML, echo.MIMEApplicationJSON} {
		t.Run(accept, func(t *testing.T) {
			var body bytes.Buffer
			w := multipart.NewWriter(&body)
			if _, err := w.CreateFormFile("files", "bad?.txt"); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"ttl", "ttlViews"} {
				if err := w.WriteField(name, "1"); err != nil {
					t.Fatal(err)
				}
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/file", &body)
			req.Header.Set(echo.HeaderContentType, w.FormDataContentType())
			req.Header.Set(echo.HeaderAccept, accept)
			rec := httptest.NewRecorder()
			if err := AddFile(e.NewContext(req, rec)); err != nil {
				t.Fatal(err)
			}
			wantRefresh := "3; url=/file"
			wantMessage := "Invalid or duplicate file name"
			if accept == echo.MIMEApplicationJSON {
				wantRefresh = ""
				wantMessage = "Invalid multipart upload"
			}
			if rec.Code != http.StatusBadRequest || rec.Header().Get("Refresh") != wantRefresh ||
				!strings.Contains(rec.Body.String(), wantMessage) {
				t.Fatalf("status=%d refresh=%q body=%q", rec.Code, rec.Header().Get("Refresh"), rec.Body.String())
			}
		})
	}
}

func TestDisplayErrorPreservesUnicode(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"", ""},
		{"already capitalized", "Already capitalized"},
		{"Invalid file", "Invalid file"},
		{"échec", "Échec"},
	} {
		if got := displayError(tc.input); got != tc.want {
			t.Errorf("displayError(%q) = %q; want %q", tc.input, got, tc.want)
		}
	}
}
