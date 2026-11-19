package router

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func tusRequest(f *fileSessionFixture, method, index, offset, version, bearer, csrf string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://example.test"+sessionPath+"/"+f.id+"/files/"+index, body)
	r.RemoteAddr = "127.0.0.1:39003"
	r.AddCookie(f.cookie)
	r.Header.Set("X-CSRF-Token", csrf)
	r.Header.Set("Authorization", "Bearer "+bearer)
	if version != "" {
		r.Header.Set("Tus-Resumable", version)
	}
	if method == "PATCH" {
		r.Header.Set("Content-Type", "application/offset+octet-stream")
		r.Header.Set("Upload-Offset", offset)
	}
	rec := httptest.NewRecorder()
	f.e.ServeHTTP(rec, r)
	return rec
}

func TestTusTransferAndPublication(t *testing.T) {
	f := newFileSessionFixture(t)
	f.prepare("blocks")
	t.Setenv("OKURU_UPLOAD_MAX_PATCH_BYTES", "4")
	run := func(method, index, offset string, body io.Reader) *httptest.ResponseRecorder {
		return tusRequest(f, method, index, offset, "1.0.0", f.bearer, f.csrf, body)
	}
	if r := run("OPTIONS", "0", "", nil); r.Code != 204 || r.Header().Get("Tus-Version") != "1.0.0" || r.Header().Get("Tus-Extension") != "" {
		t.Fatal("incorrect tus discovery", r.Code)
	}
	if r := tusRequest(f, "HEAD", "0", "", "0.2", f.bearer, "", nil); r.Code != 412 || r.Header().Get("Tus-Version") != "1.0.0" || !strings.Contains(r.Header().Get("Cache-Control"), "no-store") {
		t.Fatal("unsupported version", r.Code)
	}
	if r := tusRequest(f, "HEAD", "0", "", "1.0.0", "invalid", "", nil); r.Code != 404 {
		t.Fatal("wrong credential", r.Code)
	}
	if r := tusRequest(f, "PATCH", "0", "0", "1.0.0", f.bearer, "invalid", strings.NewReader("x")); r.Code != 403 {
		t.Fatal("wrong CSRF", r.Code)
	}
	if r := run("HEAD", "1", "", nil); r.Code != 200 || r.Header().Get("Upload-Length") != "0" || r.Header().Get("Upload-Offset") != "0" {
		t.Fatal("empty resource", r.Code)
	}
	if r := run("PATCH", "1", "0", nil); r.Code != 204 || r.Header().Get("Upload-Offset") != "0" {
		t.Fatal("empty PATCH", r.Code, r.Body.String())
	}
	if r := run("PATCH", "0", "0", io.NopCloser(strings.NewReader("abcde"))); r.Code != 413 {
		t.Fatal("chunked limit", r.Code)
	}
	if r := run("PATCH", "0", "0", bytes.NewBufferString("abcd")); r.Code != 204 || r.Header().Get("Upload-Offset") != "4" {
		t.Fatal("first chunk", r.Code, r.Body.String())
	}
	if r := run("PATCH", "0", "0", strings.NewReader("abcd")); r.Code != 409 {
		t.Fatal("stale offset", r.Code)
	}
	if r := run("HEAD", "0", "", nil); r.Code != 200 || r.Header().Get("Upload-Offset") != "4" || r.Header().Get("Upload-Length") != "6" {
		t.Fatal("lost response recovery", r.Code)
	}
	if r := run("PATCH", "0", "4", io.NopCloser(strings.NewReader("efg"))); r.Code != 413 {
		t.Fatal("manifest limit", r.Code)
	}
	if r := run("PATCH", "0", "4", io.NopCloser(strings.NewReader("ef"))); r.Code != 204 || r.Header().Get("Upload-Offset") != "6" {
		t.Fatal("last chunk", r.Code)
	}
	complete := sessionPath + "/" + f.id + "/complete"
	f.checkPublication(f.call("POST", complete, "", nil))
	if rec := f.call("POST", complete, "", nil); rec.Code != 200 {
		t.Fatal("replayed completion", rec.Code)
	}
}

type gatedTusBody struct {
	started chan struct{}
	resume  chan struct{}
	data    *strings.Reader
}

func (b *gatedTusBody) Read(dst []byte) (int, error) {
	if b.started != nil {
		close(b.started)
		b.started = nil
		<-b.resume
	}
	return b.data.Read(dst)
}

func TestTusConcurrentWritersAndCancellation(t *testing.T) {
	f := newFileSessionFixture(t)
	f.prepare("blocks")
	start, resume := make(chan struct{}), make(chan struct{})
	b := &gatedTusBody{start, resume, strings.NewReader("ab")}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- tusRequest(f, "PATCH", "0", "0", "1.0.0", f.bearer, f.csrf, b) }()
	select {
	case <-start:
	case rec := <-done:
		t.Fatalf("PATCH refused before reading: %d", rec.Code)
	case <-time.After(5 * time.Second):
		t.Fatal("PATCH did not start")
	}
	second := tusRequest(f, "PATCH", "0", "0", "1.0.0", f.bearer, f.csrf, strings.NewReader("zz"))
	cancel := f.call(http.MethodDelete, sessionPath+"/"+f.id, "", nil)
	close(resume)
	first := <-done
	if first.Code != 204 || (second.Code != 409 && second.Code != 429) || cancel.Code != 409 {
		t.Fatalf("first=%d second=%d cancel=%d", first.Code, second.Code, cancel.Code)
	}
	if rec := f.call(http.MethodDelete, sessionPath+"/"+f.id, "", nil); rec.Code != 204 {
		t.Fatal("cancel", rec.Code)
	}
	if rec := tusRequest(f, "HEAD", "0", "", "1.0.0", f.bearer, f.csrf, nil); rec.Code != 410 {
		t.Fatal("cancelled transfer", rec.Code)
	}
}
