package router

import (
	"crypto/sha512"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/flosch/pongo2"
	"github.com/labstack/echo/v5"
	"golang.org/x/net/html"
)

// Renderer loads templates alongside the executable. A copied test binary lets
// this exercise the real renderer against the real views without altering any
// shared build cache or relying on the current process working directory.
func TestRendererNonceResponses(t *testing.T) {
	if os.Getenv("OKURU_CSP_TEST_HELPER") != "1" {
		dir := t.TempDir()
		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, "router.test")
		copyNonceFixture(t, exe, target, 0700)
		entries, err := os.ReadDir("../views")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "views"), 0700); err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			copyNonceFixture(t, filepath.Join("../views", entry.Name()), filepath.Join(dir, "views", entry.Name()), 0600)
		}
		scriptsDir := filepath.Join(dir, "public", "scripts")
		if err := os.MkdirAll(scriptsDir, 0700); err != nil {
			t.Fatal(err)
		}
		scripts, err := os.ReadDir("../public/scripts")
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range scripts {
			if entry.Type().IsRegular() {
				copyNonceFixture(t, filepath.Join("../public/scripts", entry.Name()), filepath.Join(scriptsDir, entry.Name()), 0600)
			}
		}
		cmd := exec.Command(target, "-test.run=^TestRendererNonceResponses$", "-test.v")
		cmd.Env = append(os.Environ(), "OKURU_CSP_TEST_HELPER=1")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("renderer subprocess failed: %v\n%s", err, output)
		}
		// A modified served asset must make the same rendered-page check fail.
		bootstrap := filepath.Join(scriptsDir, "bootstrap.min.js")
		asset, err := os.ReadFile(bootstrap)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(bootstrap, append(asset, '\n'), 0600); err != nil {
			t.Fatal(err)
		}
		cmd = exec.Command(target, "-test.run=^TestRendererNonceResponses$", "-test.v")
		cmd.Env = append(os.Environ(), "OKURU_CSP_TEST_HELPER=1")
		output, err = cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(output), "integrity for") {
			t.Fatalf("tampered asset was not rejected: %v\n%s", err, output)
		}
		return
	}

	e := echo.New()
	e.Renderer = Renderer{Debug: true}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	scriptsDir := filepath.Join(filepath.Dir(executable), "public", "scripts")
	// A failed render must never emit a partial document under a missing or
	// mismatched policy. Echo buffers the response until rendering succeeds.
	for _, tc := range []struct {
		name string
		data any
	}{
		{"does-not-exist.html", pongo2.Context{}},
		{"set_password.html", "invalid template context"},
	} {
		rec := httptest.NewRecorder()
		c := e.NewContext(httptest.NewRequest(http.MethodGet, "/", nil), rec)
		if err := c.Render(http.StatusOK, tc.name, tc.data); err == nil {
			t.Fatalf("%s: expected rendering failure", tc.name)
		}
		if rec.Body.Len() != 0 || rec.Header().Get("Content-Security-Policy") != "" {
			t.Fatalf("%s: failed render exposed output", tc.name)
		}
	}
	seen := map[string]bool{}
	for _, name := range []string{"set_password.html", "index_file.html", "confirm.html", "confirm_file.html", "password.html", "403.html", "file.html"} {
		for attempt := 0; attempt < 2; attempt++ {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			// Conditional requests must not reuse a nonce-bearing HTML body.
			req.Header.Set("If-None-Match", `"stale"`)
			c := e.NewContext(req, rec)
			if err := c.Render(http.StatusOK, name, pongo2.Context{}); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: status %d", name, rec.Code)
			}
			policy := rec.Header().Get("Content-Security-Policy")
			if strings.Contains(strings.ToLower(policy), "sha256-") {
				t.Fatalf("%s: SHA remains in CSP: %s", name, policy)
			}
			if !strings.Contains(strings.ToLower(rec.Header().Get("Cache-Control")), "no-store") {
				t.Fatalf("%s: cache policy %q", name, rec.Header().Get("Cache-Control"))
			}
			var source string
			for _, directive := range strings.Split(policy, ";") {
				fields := strings.Fields(directive)
				if len(fields) > 0 && fields[0] == "script-src" {
					if len(fields) != 2 || !strings.HasPrefix(fields[1], "'nonce-") || !strings.HasSuffix(fields[1], "'") {
						t.Fatalf("%s: non-strict script policy %q", name, directive)
					}
					source = strings.TrimSuffix(strings.TrimPrefix(fields[1], "'nonce-"), "'")
				}
			}
			raw, err := base64.StdEncoding.DecodeString(source)
			if err != nil || len(raw) < 16 {
				t.Fatalf("%s: invalid nonce %q", name, source)
			}
			if seen[source] {
				t.Fatalf("%s: reused nonce", name)
			}
			seen[source] = true
			doc, err := html.Parse(strings.NewReader(rec.Body.String()))
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			externalCount := 0
			var visit func(*html.Node)
			visit = func(n *html.Node) {
				if n.Type == html.ElementNode && n.Data == "script" {
					count++
					nonce := ""
					src := ""
					integrity := ""
					for _, attr := range n.Attr {
						switch attr.Key {
						case "nonce":
							nonce = attr.Val
						case "src":
							src = attr.Val
						case "integrity":
							integrity = attr.Val
						}
					}
					if nonce != source {
						t.Errorf("%s: script nonce %q differs from policy", name, nonce)
					}
					if src != "" {
						externalCount++
						parsed, err := url.Parse(src)
						if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
							t.Errorf("%s: unexpected script URL %q", name, src)
						} else {
							path := strings.TrimPrefix(parsed.Path, "/")
							if !strings.HasPrefix(path, "scripts/") || strings.Contains(strings.TrimPrefix(path, "scripts/"), "/") {
								t.Errorf("%s: unexpected script path %q", name, src)
							} else {
								asset, err := os.ReadFile(filepath.Join(scriptsDir, strings.TrimPrefix(path, "scripts/")))
								if err != nil {
									t.Errorf("%s: read script %q: %v", name, src, err)
								} else {
									digest := sha512.Sum512(asset)
									want := "sha512-" + base64.StdEncoding.EncodeToString(digest[:])
									if integrity != want {
										t.Errorf("%s: integrity for %q = %q, want %q", name, src, integrity, want)
									}
								}
							}
						}
					}
				}
				for child := n.FirstChild; child != nil; child = child.NextSibling {
					visit(child)
				}
			}
			visit(doc)
			if count == 0 {
				t.Errorf("%s: no script elements exercised", name)
			}
			if externalCount == 0 {
				t.Errorf("%s: no external script elements exercised", name)
			}
		}
	}
}

func copyNonceFixture(t *testing.T, src, dst string, mode os.FileMode) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		t.Fatal(err)
	}
	if err := out.Close(); err != nil {
		t.Fatal(err)
	}
}
