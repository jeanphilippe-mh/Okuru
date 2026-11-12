package controllers

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

type errorMessageRenderer struct{}

func (errorMessageRenderer) Render(w io.Writer, _ string, data interface{}, _ echo.Context) error {
	_, err := fmt.Fprint(w, data)
	return err
}

func TestUploadValidationBoundsFilesBeforeStorage(t *testing.T) {
	oldSize := MaxFileSize
	MaxFileSize = 10
	t.Cleanup(func() { MaxFileSize = oldSize })
	for name, files := range map[string][]*SecureMultipartFile{
		"empty":                  nil,
		"too many":               make([]*SecureMultipartFile, maxUploadFiles+1),
		"duplicate":              {{Filename: "same.txt", Size: 1}, {Filename: "same.txt", Size: 1}},
		"unicode duplicate":      {{Filename: "résumé.txt", Size: 1}, {Filename: "re\u0301sume\u0301.txt", Size: 1}},
		"case duplicate":         {{Filename: "Report.txt", Size: 1}, {Filename: "report.TXT", Size: 1}},
		"unicode case duplicate": {{Filename: "É.txt", Size: 1}, {Filename: "é.txt", Size: 1}},
		"unicode fold expansion": {{Filename: "Straße.txt", Size: 1}, {Filename: "STRASSE.TXT", Size: 1}},
		"combined size":          {{Filename: "a.txt", Size: 6}, {Filename: "b.txt", Size: 5}},
		"invalid name":           {{Filename: "..", Size: 1}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := validateUploadFiles(files); err == nil {
				t.Fatal("invalid files were accepted")
			}
		})
	}
	if _, err := validateUploadFiles([]*SecureMultipartFile{{Filename: "a.txt", Size: 5}, {Filename: "b.txt", Size: 5}}); err != nil {
		t.Fatalf("valid files rejected: %v", err)
	}
	name := "re\u0301sume\u0301 + 🔐.txt"
	names, err := validateUploadFiles([]*SecureMultipartFile{{Filename: name, Size: 1}})
	if err != nil || len(names) != 1 || names[0] != name {
		t.Fatalf("valid original name was not preserved: %q, %v", names, err)
	}
}

func TestEmptyMultipartRejectedWithoutRedis(t *testing.T) {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	_ = w.WriteField("ttl", "1")
	_ = w.WriteField("ttlViews", "1")
	_ = w.Close()
	e := echo.New()
	e.Renderer = testRenderer{}
	e.Validator = uploadValidator{}
	req := httptest.NewRequest(http.MethodPost, "/file", &body)
	req.Header.Set(echo.HeaderContentType, w.FormDataContentType())
	rec := httptest.NewRecorder()
	if err := AddFile(e.NewContext(req, rec)); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("empty upload status = %d", rec.Code)
	}
}

func TestOversizedSecretsRejectedBeforeRedis(t *testing.T) {
	secret := strings.Repeat("s", MaxSecretBytes+1)
	t.Run("web", func(t *testing.T) {
		e := echo.New()
		e.Renderer = testRenderer{}
		form := url.Values{"password": {secret}, "ttl": {"1"}, "ttlViews": {"1"}}
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		if err := AddIndex(e.NewContext(req, rec)); err != nil || rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, error = %v", rec.Code, err)
		}
	})
	t.Run("json", func(t *testing.T) {
		e := echo.New()
		req := httptest.NewRequest(http.MethodPost, "/api/v1", strings.NewReader(`{"password":"`+secret+`"}`))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		err := CreatePassword(e.NewContext(req, rec))
		if httpErr, ok := err.(*echo.HTTPError); !ok || httpErr.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("expected HTTP 413, got %v", err)
		}
	})
	t.Run("download", func(t *testing.T) {
		e := echo.New()
		form := url.Values{"password": {secret}}
		req := httptest.NewRequest(http.MethodPost, "/file/unused", strings.NewReader(form.Encode()))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
		rec := httptest.NewRecorder()
		ctx := e.NewContext(req, rec)
		ctx.SetParamNames("file_key")
		ctx.SetParamValues("00000000-0000-4000-8000-000000000000" + TOKEN_SEPARATOR + "key")
		if err := DownloadFile(ctx); err != nil || rec.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, error = %v", rec.Code, err)
		}
	})
}

func TestMalformedNumericFieldIsNotEchoedOrLogged(t *testing.T) {
	marker := "bad-TTL-42"
	form := url.Values{"password": {"secret"}, "ttl": {marker}, "ttlViews": {"1"}}
	e := echo.New()
	e.Renderer = errorMessageRenderer{}
	req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationForm)
	rec := httptest.NewRecorder()
	logger := log.StandardLogger()
	oldOutput := logger.Out
	var logs bytes.Buffer
	logger.SetOutput(&logs)
	t.Cleanup(func() { logger.SetOutput(oldOutput) })
	if err := AddIndex(e.NewContext(req, rec)); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), marker) || strings.Contains(logs.String(), marker) {
		t.Fatalf("malformed field leaked or was accepted: status %d", rec.Code)
	}
}
