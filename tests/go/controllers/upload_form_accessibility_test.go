package controllers

import (
	"bytes"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/flosch/pongo2"
	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
)

type uploadFormTemplateRenderer struct{ templates *pongo2.TemplateSet }

func (r uploadFormTemplateRenderer) Render(w io.Writer, name string, data interface{}, _ echo.Context) error {
	template, err := r.templates.FromFile(name)
	if err != nil {
		return err
	}
	return template.ExecuteWriter(data.(pongo2.Context), w)
}

func TestUploadFormPreservesLimitsAndAccessibilityAfterError(t *testing.T) {
	oldFolder, oldSize := FILEFOLDER, MaxFileSize
	FILEFOLDER, MaxFileSize = t.TempDir(), 1024*1024*1024
	t.Cleanup(func() { FILEFOLDER, MaxFileSize = oldFolder, oldSize })

	loader, err := pongo2.NewLocalFileSystemLoader("../views")
	if err != nil {
		t.Fatal(err)
	}
	e := echo.New()
	e.Renderer = uploadFormTemplateRenderer{templates: pongo2.NewSet("upload-form-test", loader)}
	e.Validator = uploadValidator{}

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("ttl", "1"); err != nil {
		t.Fatal(err)
	}
	if err := mw.WriteField("ttlViews", "1"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name string
		run  func(echo.Context) error
		req  *http.Request
		want int
	}{
		{"initial form", IndexFile, httptest.NewRequest(http.MethodGet, "/file", nil), http.StatusOK},
		{"validation error", AddFile, httptest.NewRequest(http.MethodPost, "/file", &body), http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.req.Method == http.MethodPost {
				test.req.Header.Set(echo.HeaderContentType, mw.FormDataContentType())
			}
			recorder := httptest.NewRecorder()
			ctx := e.NewContext(test.req, recorder)
			ctx.Set("csrf", "csrf-test")
			if err := test.run(ctx); err != nil {
				t.Fatal(err)
			}
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d", recorder.Code, test.want)
			}
			for _, want := range []string{
				"total max size <b>1 GB</b>",
				"const maxsizeBytes = 1073741824;",
				`aria-describedby="password-help"`,
				`id="password-help"`,
				`<span role="alert">`,
				`value="csrf-test"`,
			} {
				if !strings.Contains(recorder.Body.String(), want) {
					t.Errorf("rendered form is missing %q", want)
				}
			}
		})
	}
}
