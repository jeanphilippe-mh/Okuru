package utils

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

type directTestPart struct {
	field    string
	filename string
	mimeType string
	content  string
}

func directTestRequest(t *testing.T, parts ...directTestPart) *http.Request {
	t.Helper()
	var body bytes.Buffer
	writer := multipart.NewWriter(&body)
	for _, p := range parts {
		header := make(textproto.MIMEHeader)
		params := map[string]string{"name": p.field}
		if p.filename != "" {
			params["filename"] = p.filename
		}
		header.Set("Content-Disposition", mime.FormatMediaType("form-data", params))
		if p.mimeType != "" {
			header.Set("Content-Type", p.mimeType)
		}
		out, err := writer.CreatePart(header)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(out, p.content); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/api/v2/files", &body)
	r.Header.Set("Content-Type", writer.FormDataContentType())
	return r
}

func TestDirectFileMultipartPlainMetadata(t *testing.T) {
	root := t.TempDir()
	metadata := `{"ttl_seconds":604800,"views":100,"files":[{"name":"empty","size":0}]}`
	r := directTestRequest(t, directTestPart{"metadata", "", "application/json", metadata}, directTestPart{"files", "empty", "", ""})
	form, err := ParseDirectFileMultipart(r, root, 1, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer form.Close()
	if form.DirectMetadata.Deletable || form.DirectMetadata.Password != "" {
		t.Fatal("omitted optional fields changed their defaults")
	}
}

const directExample = `{"ttl_seconds":300,"views":2,"deletable":true,"password":"private","files":[{"name":"empty","size":0},{"name":"a.txt","size":3}]}`

func TestDirectFileMultipart(t *testing.T) {
	root := t.TempDir()
	r := directTestRequest(t, directTestPart{"metadata", "blob", "application/json; charset=utf-8", directExample},
		directTestPart{"files", "empty", "", ""}, directTestPart{"files", "a.txt", "", "abc"})
	form, err := ParseDirectFileMultipart(r, root, 3, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer form.Close()
	m := form.DirectMetadata
	if m == nil || m.TTLSeconds != 300 || m.Views != 2 || !m.Deletable || m.Password != "private" || len(m.Files) != 2 {
		t.Fatal("direct metadata was not retained")
	}
	if m.Files[1] != (DirectFileSpec{Name: "a.txt", Size: 3}) || len(form.Files) != 2 || form.Files[0].Size != 0 {
		t.Fatal("manifest or actual files were changed")
	}
	plain, err := form.Files[1].Open()
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(plain)
	_ = plain.Close()
	if err != nil || string(got) != "abc" {
		t.Fatalf("decrypted payload = %q, %v", got, err)
	}
	if GetSecureMultipart(r) != form || r.FormValue("password") != "" {
		t.Fatal("cached form or JSON password isolation was lost")
	}
	cached, err := ParseDirectFileMultipart(r, root, 3, 2)
	if cached != form || err != nil {
		t.Fatal("direct parser was not repeatable on the same request")
	}
}

func TestDirectFileMultipartRejectsInvalidMetadata(t *testing.T) {
	for _, tc := range []struct {
		name string
		from string
		to   string
		want error
	}{
		{"missing duration", `"ttl_seconds":300,`, "", ErrSecureMultipart},
		{"duration", "300", "299", ErrSecureMultipart},
		{"views", `"views":2`, `"views":101`, ErrSecureMultipart},
		{"type", `"views":2`, `"views":"2"`, ErrSecureMultipart},
		{"unknown", `"views":2`, `"Views":2`, ErrSecureMultipart},
		{"duplicate", `"views":2`, `"views":1,"\u0076iews":2`, ErrSecureMultipart},
		{"null boolean", "true", "null", ErrSecureMultipart},
		{"null password", `"private"`, "null", ErrSecureMultipart},
		{"null nested size", `"size":0`, `"size":null`, ErrSecureMultipart},
		{"null file", `{"name":"empty","size":0}`, "null", ErrSecureMultipart},
		{"password limit", "private", strings.Repeat("s", MaxSecretBytes+1), ErrSecureMultipartTooLarge},
		{"negative size", `"size":0`, `"size":-1`, ErrSecureMultipart},
		{"fractional size", `"size":0`, `"size":0.5`, ErrSecureMultipart},
		{"unrepresentable size", `"size":0`, `"size":9223372036854775808`, ErrSecureMultipart},
		{"missing size", `,"size":0`, "", ErrSecureMultipart},
		{"nested duplicate", `"size":0`, `"size":1,"size":0`, ErrSecureMultipart},
		{"unknown file key", `"size":0`, `"size":0,"mime":"text/plain"`, ErrSecureMultipart},
		{"size sum", `"size":0`, `"size":1`, ErrSecureMultipartTooLarge},
		{"traversal", "empty", "../empty", ErrSecureMultipartFilename},
		{"colliding names", "empty", "A.TXT", ErrSecureMultipartFilename},
		{"no files", `[{"name":"empty","size":0},{"name":"a.txt","size":3}]`, "[]", ErrSecureMultipart},
		{"file count", `"size":3}`, `"size":3},{"name":"b","size":0}`, ErrSecureMultipartTooLarge},
		{"trailing value", "]}", "]} {}", ErrSecureMultipart},
		{"metadata limit", "private", strings.Repeat("p", 64<<10), ErrSecureMultipartTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			meta := strings.Replace(directExample, tc.from, tc.to, 1)
			r := directTestRequest(t, directTestPart{"metadata", "", "application/json", meta})
			if _, err := ParseDirectFileMultipart(r, root, 3, 2); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
			if files, err := os.ReadDir(root); err != nil || len(files) != 0 {
				t.Fatal("invalid metadata left staging on disk")
			}
		})
	}
}

func TestDirectFileMultipartPreservesBodyErrors(t *testing.T) {
	meta := directTestPart{"metadata", "", "application/json", directExample}
	empty := directTestPart{"files", "empty", "", ""}
	file := directTestPart{"files", "a.txt", "", "PAY"}
	bodyFailure := &http.MaxBytesError{Limit: 256}
	for _, marker := range []string{"Content-Disposition", "private", "PAY"} {
		t.Run(marker, func(t *testing.T) {
			r := directTestRequest(t, meta, empty, file)
			all, err := io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			off := bytes.Index(all, []byte(marker))
			if off < 0 {
				t.Fatal("test marker missing")
			}
			r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(all[:off+1]), iotest.ErrReader(bodyFailure)))
			root := t.TempDir()
			if _, err := ParseDirectFileMultipart(r, root, 100, 2); !errors.Is(err, bodyFailure) {
				t.Fatalf("body failure lost: %v", err)
			}
			if files, err := os.ReadDir(root); err != nil || len(files) != 0 {
				t.Fatal("interrupted body left staged files")
			}
		})
	}
}

func TestDirectFileMultipartExcessDoesNotDrain(t *testing.T) {
	boundary := "boundary"
	prefix := "--boundary\r\nContent-Disposition: form-data; name=\"metadata\"\r\nContent-Type: application/json\r\n\r\n" +
		`{"ttl_seconds":300,"views":1,"files":[{"name":"a","size":1}]}` +
		"\r\n--boundary\r\nContent-Disposition: form-data; name=\"files\"; filename=\"a\"\r\n\r\n"
	release := make(chan struct{})
	defer close(release)
	body := io.MultiReader(strings.NewReader(prefix), strings.NewReader(strings.Repeat("x", 8192)), multipartBlockingTail{release})
	r := httptest.NewRequest("POST", "/api/v2/files", body)
	r.Header.Set("Content-Type", "multipart/form-data; boundary="+boundary)
	root := t.TempDir()
	result := make(chan error, 1)
	go func() {
		_, err := ParseDirectFileMultipart(r, root, 1<<20, 1)
		result <- err
	}()
	select {
	case err := <-result:
		if !errors.Is(err, ErrSecureMultipart) {
			t.Fatalf("declared size mismatch error = %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("parser waited for bytes beyond the declared size")
	}
}

func TestDirectFileMultipartRejectsPartMismatch(t *testing.T) {
	meta := directTestPart{"metadata", "", "application/json", directExample}
	empty := directTestPart{"files", "empty", "", ""}
	file := directTestPart{"files", "a.txt", "", "abc"}
	for _, tc := range []struct {
		name  string
		parts []directTestPart
	}{
		{"missing metadata", []directTestPart{empty, file}},
		{"invalid metadata media type", []directTestPart{{"metadata", "", "text/plain", directExample}, empty, file}},
		{"missing file", []directTestPart{meta, empty}},
		{"wrong order", []directTestPart{meta, file, empty}},
		{"additional part", []directTestPart{meta, empty, file, file}},
		{"repeated metadata", []directTestPart{meta, empty, meta}},
		{"file path shortened by multipart", []directTestPart{meta, empty, {"files", "nested/a.txt", "", "abc"}}},
		{"shorter", []directTestPart{meta, empty, {"files", "a.txt", "", "ab"}}},
		{"longer", []directTestPart{meta, empty, {"files", "a.txt", "", "abcd"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			r := directTestRequest(t, tc.parts...)
			if form, err := ParseDirectFileMultipart(r, root, 100, 3); err == nil || form != nil {
				t.Fatal("invalid parts were accepted")
			}
			if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
				t.Fatal("staged ciphertext survived rejection")
			}
		})
	}
}
