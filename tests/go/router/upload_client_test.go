package router

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeanphilippe-mh/Okuru/models"
	"github.com/jeanphilippe-mh/Okuru/utils"
)

const qualificationSize int64 = 440_000_000
const qualificationProxyLimit int64 = 100_000_000

type qualificationZeros struct{}

func (qualificationZeros) Read(b []byte) (int, error) { clear(b); return len(b), nil }

func qualificationSource(t *testing.T) (*os.File, []byte) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "source-*.bin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	// A fixed counter-mode stream gives reproducible, poorly compressible input
	// without retaining the 440 MB source fixture in memory.
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	stream := cipher.StreamReader{S: cipher.NewCTR(block, make([]byte, aes.BlockSize)), R: qualificationZeros{}}
	h := sha256.New()
	if n, err := io.CopyN(io.MultiWriter(f, h), stream, qualificationSize); err != nil || n != qualificationSize {
		t.Fatalf("source size=%d error=%v", n, err)
	}
	return f, h.Sum(nil)
}

type qualificationBody struct {
	io.ReadCloser
	n atomic.Int64
}

func (b *qualificationBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n.Add(int64(n))
	return n, err
}

type qualificationProxy struct {
	sync.Mutex
	sizes   []int64
	dropped bool
}

func (p *qualificationProxy) handler(upstream *url.URL) http.Handler {
	proxy := httputil.NewSingleHostReverseProxy(upstream)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ContentLength > qualificationProxyLimit {
			http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
			return
		}
		if r.Method != http.MethodPatch {
			proxy.ServeHTTP(w, r)
			return
		}
		body := &qualificationBody{ReadCloser: http.MaxBytesReader(w, r.Body, qualificationProxyLimit)}
		r.Body = body
		// ModifyResponse runs only after the origin has decided the PATCH outcome.
		// Abort the first successful response at the proxy before its headers can
		// reach the client. This exercises genuine lost-response recovery via HEAD.
		single := *proxy
		single.ModifyResponse = func(resp *http.Response) error {
			if resp.StatusCode != http.StatusNoContent {
				return nil
			}
			p.Lock()
			p.sizes = append(p.sizes, body.n.Load())
			drop := !p.dropped
			p.dropped = true
			p.Unlock()
			if drop {
				_ = resp.Body.Close()
				panic(http.ErrAbortHandler)
			}
			return nil
		}
		single.ServeHTTP(w, r)
	})
}

type qualificationClient struct {
	t                        *testing.T
	client                   *http.Client
	origin, id, bearer, csrf string
}

func (c *qualificationClient) request(method, path string, body io.Reader) *http.Request {
	c.t.Helper()
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		c.t.Fatal("unexpected published path")
	}
	r, err := http.NewRequestWithContext(c.t.Context(), method, c.origin+path, body)
	if err != nil {
		c.t.Fatal(err)
	}
	r.Header.Set("Sec-Fetch-Site", "same-origin")
	if strings.HasPrefix(path, sessionPath+"/") || path == sessionPath {
		r.Header.Set("Authorization", "Bearer "+c.bearer)
		if method != http.MethodGet && method != http.MethodHead && c.csrf != "" {
			r.Header.Set("X-CSRF-Token", c.csrf)
		}
	}
	return r
}
func (c *qualificationClient) expect(r *http.Request, status int) *http.Response {
	c.t.Helper()
	res, err := c.client.Do(r)
	if err != nil {
		c.t.Fatalf("%s transport failed (%T)", r.Method, err)
	}
	if res.StatusCode != status {
		// Error messages are limited to the public code; do not log a share URL,
		// cookie, Authorization header or returned archive.
		var fault struct{ Code string }
		_ = json.NewDecoder(io.LimitReader(res.Body, 4096)).Decode(&fault)
		res.Body.Close()
		c.t.Fatalf("%s returned %d, wanted %d (code %s)", r.Method, res.StatusCode, status, fault.Code)
	}
	return res
}

func (c *qualificationClient) head(path string) int64 {
	c.t.Helper()
	req := c.request(http.MethodHead, path, nil)
	req.Header.Set("Tus-Resumable", "1.0.0")
	res := c.expect(req, http.StatusOK)
	defer res.Body.Close()
	offset, err := strconv.ParseInt(res.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || res.Header.Get("Upload-Length") != strconv.FormatInt(qualificationSize, 10) || res.Header.Get("Tus-Resumable") != "1.0.0" {
		c.t.Fatal("incorrect tus HEAD")
	}
	return offset
}
func (c *qualificationClient) prepare(wantMaxPatch int64) string {
	c.t.Helper()
	res := c.expect(c.request(http.MethodGet, uploadBootstrapPath, nil), http.StatusOK)
	c.csrf = res.Header.Get("X-CSRF-Token")
	var boot struct {
		Modes    []string `json:"modes"`
		MaxPatch int64    `json:"max_patch_bytes"`
	}
	err := json.NewDecoder(res.Body).Decode(&boot)
	res.Body.Close()
	if err != nil || c.csrf == "" || boot.MaxPatch != wantMaxPatch || !slices.Contains(boot.Modes, "blocks") {
		c.t.Fatal("bootstrap did not advertise the expected blocks mode")
	}
	manifest := fmt.Sprintf(`{"mode":"blocks","views":1,"ttl_seconds":3600,"files":[{"name":"qualification.bin","size":%d}]}`, qualificationSize)
	req := c.request(http.MethodPost, sessionPath, strings.NewReader(manifest))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Idempotency-Key", c.id)
	res = c.expect(req, http.StatusCreated)
	defer res.Body.Close()
	var session struct {
		ID    string
		Files []struct {
			URL string `json:"upload_url"`
		}
	}
	if json.NewDecoder(res.Body).Decode(&session) != nil || session.ID != c.id || len(session.Files) != 1 {
		c.t.Fatal("incomplete preparation")
	}
	return session.Files[0].URL
}

func (c *qualificationClient) send(source *os.File, path string, chunk int64) []int64 {
	c.t.Helper()
	offset := c.head(path)
	if offset != 0 {
		c.t.Fatal("new upload had a non-zero offset")
	}
	var expected []int64
	for offset < qualificationSize {
		n := min(chunk, qualificationSize-offset)
		r := c.request(http.MethodPatch, path, io.NewSectionReader(source, offset, n))
		r.ContentLength = n
		r.Header.Set("Content-Type", "application/offset+octet-stream")
		r.Header.Set("Tus-Resumable", "1.0.0")
		r.Header.Set("Upload-Offset", strconv.FormatInt(offset, 10))
		if offset == 0 {
			res, err := c.client.Do(r)
			if res != nil {
				res.Body.Close()
			}
			if err == nil {
				c.t.Fatal("the proxy did not drop the first response")
			}
			if c.head(path) != n {
				c.t.Fatal("HEAD did not recover the fully confirmed first block")
			}
		} else {
			res := c.expect(r, http.StatusNoContent)
			res.Body.Close()
			if res.Header.Get("Upload-Offset") != strconv.FormatInt(offset+n, 10) {
				c.t.Fatal("invalid acknowledged byte offset")
			}
		}
		expected = append(expected, n)
		offset += n
	}
	if c.head(path) != qualificationSize {
		c.t.Fatal("incorrect final tus offset")
	}
	return expected
}

func (c *qualificationClient) publish() string {
	c.t.Helper()
	res := c.expect(c.request(http.MethodPost, sessionPath+"/"+c.id+"/complete", nil), http.StatusCreated)
	defer res.Body.Close()
	var result struct{ Link string }
	if json.NewDecoder(res.Body).Decode(&result) != nil || !strings.HasPrefix(result.Link, "/file/") {
		c.t.Fatal("missing canonical file link")
	}
	return result.Link
}
func (c *qualificationClient) verifyDownload(path string, want []byte) {
	c.t.Helper()
	preview := c.expect(c.request(http.MethodGet, path, nil), http.StatusOK)
	preview.Body.Close()
	record := &models.File{FileKey: strings.TrimPrefix(path, "/file/")}
	if err := utils.GetFile(record); err != nil || record.Views != 1 {
		c.t.Fatal("preview consumed the only view")
	}
	download := func() *http.Request {
		req := c.request(http.MethodPost, path, strings.NewReader("password="))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}
	res := c.expect(download(), http.StatusOK)
	zipFile, err := os.CreateTemp(c.t.TempDir(), "received-*.zip")
	if err != nil {
		res.Body.Close()
		c.t.Fatal(err)
	}
	defer zipFile.Close()
	// The archived file is deliberately incompressible; bound the disk fixture as
	// well as all in-memory buffers if the server returns an unexpected response.
	const zipLimit = qualificationSize + 2<<20
	n, readErr := io.Copy(zipFile, io.LimitReader(res.Body, zipLimit+1))
	closeErr := res.Body.Close()
	if readErr != nil || closeErr != nil || n > zipLimit {
		c.t.Fatalf("download size=%d error=%v close=%v", n, readErr, closeErr)
	}
	z, err := zip.NewReader(zipFile, n)
	if err != nil || len(z.File) != 1 || z.File[0].Name != "qualification.bin" || z.File[0].UncompressedSize64 != uint64(qualificationSize) {
		c.t.Fatalf("invalid ZIP entry: %v", err)
	}
	plain, err := z.File[0].Open()
	if err != nil {
		c.t.Fatal(err)
	}
	got := sha256.New()
	n, err = io.Copy(got, plain)
	closeErr = plain.Close()
	if n != qualificationSize || err != nil || closeErr != nil || !bytes.Equal(got.Sum(nil), want) {
		c.t.Fatal("extracted file differs from the source")
	}
	denied := c.expect(download(), http.StatusNotFound)
	denied.Body.Close()
}

func TestUploadClientLargeProxy(t *testing.T) {
	if os.Getenv("OKURU_TEST_LARGE_UPLOADS") != "1" {
		t.Skip("enable the 440 MB proxy qualification with OKURU_TEST_LARGE_UPLOADS=1")
	}
	if os.Getenv("OKURU_TEST_REDIS_ADDR") == "" {
		t.Fatal("large-upload qualification requires an isolated Redis")
	}
	source, digest := qualificationSource(t)
	for _, profile := range []struct {
		name    string
		setting string
		chunk   int64
		patches int
		last    int64
	}{
		{"default", "", 100_000_000, 5, 40_000_000}, {"16MB", "16", 16_000_000, 28, 8_000_000},
	} {
		t.Run(profile.name, func(t *testing.T) {
			t.Setenv("OKURU_ZIP_COMPRESSION", "store")
			t.Setenv("OKURU_UPLOAD_CHUNKS_SIZE", profile.setting)
			f := newFileSessionFixture(t)
			upstream := httptest.NewServer(f.e)
			defer upstream.Close()
			u, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			meter := &qualificationProxy{}
			proxy := httptest.NewTLSServer(meter.handler(u))
			defer proxy.Close()
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			client := proxy.Client()
			client.Jar = jar
			client.Timeout = 2 * time.Minute
			c := &qualificationClient{t: t, client: client, origin: proxy.URL, id: f.id, bearer: f.bearer}
			path := c.prepare(profile.chunk)
			stop, heapPeak := make(chan struct{}), make(chan uint64, 1)
			var stopOnce sync.Once
			stopSample := func() { stopOnce.Do(func() { close(stop) }) }
			defer stopSample()
			go func() {
				ticker := time.NewTicker(100 * time.Millisecond)
				defer ticker.Stop()
				var peak uint64
				for {
					var stats runtime.MemStats
					runtime.ReadMemStats(&stats)
					peak = max(peak, stats.HeapAlloc)
					select {
					case <-stop:
						heapPeak <- peak
						return
					case <-ticker.C:
					}
				}
			}()
			start := time.Now()
			expected := c.send(source, path, profile.chunk)
			uploaded := time.Now()
			link := c.publish()
			published := time.Now()
			c.verifyDownload(link, digest)
			finished := time.Now()
			meter.Lock()
			observed := append([]int64(nil), meter.sizes...)
			dropped := meter.dropped
			meter.Unlock()
			if !dropped || len(observed) != profile.patches || observed[len(observed)-1] != profile.last || !reflect.DeepEqual(observed, expected) {
				t.Fatalf("proxy PATCH bodies=%v, expected %v", observed, expected)
			}
			stopSample()
			t.Logf("proxy_bytes=%d patches=%d first=%d last=%d upload=%s finalize=%s download_and_verify=%s peak_sampled_go_heap_MiB=%.1f source_and_extracted_sha256=%x", qualificationSize, len(observed), observed[0], observed[len(observed)-1], uploaded.Sub(start).Round(time.Millisecond), published.Sub(uploaded).Round(time.Millisecond), finished.Sub(published).Round(time.Millisecond), float64(<-heapPeak)/(1<<20), digest)
		})
	}
}
