package controllers_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	u "github.com/jeanphilippe-mh/Okuru/utils"
)

// Exercise the public TLS endpoint with Apache's production error template and a
// real Redis-backed router. Apache reaches Go over HTTP/1.1 on loopback. The
// origin deliberately interrupts the first ZIP write of each session.
func TestZIPContinuationThroughApache(t *testing.T) {
	apache := os.Getenv("OKURU_TEST_APACHE_BIN")
	if apache == "" {
		t.Skip("set OKURU_TEST_APACHE_BIN and OKURU_TEST_APACHE_MODULE_DIR to run the Apache contract")
	}
	modules := os.Getenv("OKURU_TEST_APACHE_MODULE_DIR")
	if modules == "" || os.Getenv("OKURU_TEST_REDIS_ADDR") == "" {
		t.Fatal("the Apache contract requires OKURU_TEST_APACHE_MODULE_DIR and OKURU_TEST_REDIS_ADDR")
	}
	e := resourceTest(t)
	var interruptNext atomic.Bool
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/download/") &&
			r.Header.Get("Range") == "" && interruptNext.CompareAndSwap(true, false) {
			w = interruptedZIP{w}
		}
		e.ServeHTTP(w, r)
	}))
	t.Cleanup(origin.Close)
	baseURL, roots := startDownloadContractApache(t, apache, modules, origin.URL)

	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12},
		ForceAttemptHTTP2: true,
	}
	t.Cleanup(transport.CloseIdleConnections)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		Transport:     transport,
		Jar:           jar,
		Timeout:       5 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	anonymous := *client
	anonymous.Jar = nil

	for _, scenario := range []string{"matching validator resumes", "stale validator restarts"} {
		t.Run(scenario, func(t *testing.T) {
			token, _, archive := createHTTPContractArchive(t)
			share := baseURL + "/file/" + token
			preview, _, err := apacheDownloadRequest(t, client, http.MethodGet, share, nil, "", "")
			if err != nil || preview.StatusCode != http.StatusOK {
				t.Fatalf("share preview returned %d, read error = %v", preview.StatusCode, err)
			}
			form := url.Values{}
			for _, cookie := range preview.Cookies() {
				if cookie.Name == "__Host-okuru-csrf" {
					form.Set("_csrf", cookie.Value)
				}
			}
			if form.Get("_csrf") == "" {
				t.Fatal("share preview omitted the CSRF cookie")
			}
			post, _, err := apacheDownloadRequest(t, client, http.MethodPost, share, form, "", "")
			if err != nil || post.StatusCode != http.StatusSeeOther {
				t.Fatalf("authorization returned %d, read error = %v", post.StatusCode, err)
			}
			zipPath := post.Header.Get("Location")
			if !strings.HasPrefix(zipPath, "/file/dl-") {
				t.Fatal("authorization did not redirect to the canonical ZIP path")
			}
			var downloadCookies int
			for _, cookie := range post.Cookies() {
				if strings.HasPrefix(cookie.Name, "__Secure-okuru-dl-") {
					downloadCookies++
					if cookie.Path != zipPath || cookie.Domain != "" || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
						t.Fatal("authorization lost the download cookie's scope or security attributes")
					}
				}
			}
			if downloadCookies != 1 {
				t.Fatalf("authorization issued %d download cookies, want one", downloadCookies)
			}

			zipURL := baseURL + zipPath
			interruptNext.Store(true)
			first, prefix, readErr := apacheDownloadRequest(t, client, http.MethodGet, zipURL, nil, "", "")
			if first.StatusCode != http.StatusOK || readErr == nil || !bytes.Equal(prefix, archive[:7]) {
				t.Fatalf("interrupted initial ZIP returned %d, %d bytes, read error = %v", first.StatusCode, len(prefix), readErr)
			}
			etag := first.Header.Get("ETag")
			if len(etag) < 3 || etag[0] != '"' || etag[len(etag)-1] != '"' || first.Header.Get("Last-Modified") == "" {
				t.Fatal("initial ZIP is missing a strong ETag or Last-Modified")
			}
			requireApacheZIPHeaders(t, first, etag, "", len(archive))
			byteRange := fmt.Sprintf("bytes=%d-", len(prefix))

			if scenario == "stale validator restarts" {
				resp, body, err := apacheDownloadRequest(t, client, http.MethodGet, zipURL, nil, byteRange, `"stale-fixture"`)
				if err != nil || resp.StatusCode != http.StatusOK || !bytes.Equal(body, archive) {
					t.Fatalf("stale validator returned %d, %d bytes, read error = %v", resp.StatusCode, len(body), err)
				}
				requireApacheZIPHeaders(t, resp, etag, "", len(archive))
				return
			}

			for _, rejected := range []string{fmt.Sprintf("bytes=%d-", len(archive)), "bytes=8-7"} {
				resp, body, err := apacheDownloadRequest(t, client, http.MethodGet, zipURL, nil, rejected, etag)
				if err != nil || resp.StatusCode != http.StatusRequestedRangeNotSatisfiable || len(body) != 0 ||
					resp.Header.Get("Content-Range") != fmt.Sprintf("bytes */%d", len(archive)) {
					t.Fatalf("unsatisfiable range returned %d, %d bytes, Content-Range %q, read error = %v",
						resp.StatusCode, len(body), resp.Header.Get("Content-Range"), err)
				}
			}

			assertAnonymous := func(requested, validator string) {
				t.Helper()
				resp, body, err := apacheDownloadRequest(t, &anonymous, http.MethodGet, zipURL, nil, requested, validator)
				if err != nil || resp.StatusCode != http.StatusNotFound || len(body) != 0 || resp.Header.Get("Cache-Control") != "private, no-store" {
					t.Fatalf("GET without cookie returned %d, %d bytes, read error = %v", resp.StatusCode, len(body), err)
				}
				for _, field := range []string{"Location", "ETag", "Last-Modified", "Content-Disposition", "Content-Range", "Accept-Ranges"} {
					if resp.Header.Get(field) != "" {
						t.Fatalf("GET without cookie returned %s", field)
					}
				}
				if resp.Header.Get("Content-Type") == "application/zip" {
					t.Fatal("GET without cookie advertised ZIP content")
				}
			}
			// The session is still active when the anonymous continuation is refused.
			assertAnonymous(byteRange, etag)
			partial, suffix, err := apacheDownloadRequest(t, client, http.MethodGet, zipURL, nil, byteRange, etag)
			if err != nil || partial.StatusCode != http.StatusPartialContent || !bytes.Equal(append(prefix, suffix...), archive) {
				t.Fatalf("matching validator returned %d, %d bytes, read error = %v", partial.StatusCode, len(suffix), err)
			}
			requireApacheZIPHeaders(t, partial, etag, fmt.Sprintf("bytes %d-%d/%d", len(prefix), len(archive)-1, len(archive)), len(suffix))
			if partial.Header.Get("Last-Modified") != first.Header.Get("Last-Modified") {
				t.Fatal("Last-Modified changed during continuation")
			}

			assertAnonymous("", "")
			assertAnonymous(byteRange, etag)
		})
	}
}

func apacheDownloadRequest(t *testing.T, client *http.Client, method, target string, form url.Values, byteRange, ifRange string) (*http.Response, []byte, error) {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	// Prevent transparent decoding by Go and exercise ordinary content negotiation.
	req.Header.Set("Accept-Encoding", "br, gzip")
	if byteRange != "" {
		req.Header.Set("Range", byteRange)
		req.Header.Set("If-Range", ifRange)
	}
	const clientID = "00000000-0000-4000-8000-000000000001"
	req.Header.Set(u.DownloadRequestIDHeader, clientID)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ProtoMajor != 2 || resp.TLS == nil || resp.TLS.NegotiatedProtocol != "h2" {
		t.Fatalf("Apache negotiated %s, want HTTP/2 over TLS", resp.Proto)
	}
	if strings.Contains(req.URL.Path, "/download/") {
		ids := resp.Header.Values(u.DownloadRequestIDHeader)
		if len(ids) != 1 || ids[0] == clientID || uuid.Validate(ids[0]) != nil {
			t.Fatal("Apache did not forward the single server-generated ZIP request ID")
		}
	}
	data, err := io.ReadAll(resp.Body)
	return resp, data, err
}

func requireApacheZIPHeaders(t *testing.T, resp *http.Response, etag, contentRange string, length int) {
	t.Helper()
	for name, want := range map[string]string{
		"Content-Type":     "application/zip",
		"Content-Length":   strconv.Itoa(length),
		"Content-Range":    contentRange,
		"Content-Encoding": "",
		"Accept-Ranges":    "bytes",
		"Cache-Control":    "private, no-store, no-transform",
		"ETag":             etag,
	} {
		if got := resp.Header.Get(name); got != want {
			t.Fatalf("ZIP %s = %q, want %q", name, got, want)
		}
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Disposition"), "attachment;") {
		t.Fatal("ZIP lost its attachment disposition")
	}
}

func startDownloadContractApache(t *testing.T, apache, modules, origin string) (string, *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addr := listener.Addr().String()
	writeFixture := func(name string, data []byte) string {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	tlsKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &tlsKey.PublicKey, tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(certPEM) {
		t.Fatal("cannot trust Apache's test certificate")
	}
	cert := writeFixture("cert.pem", certPEM)
	privateKey, err := x509.MarshalPKCS8PrivateKey(tlsKey)
	if err != nil {
		t.Fatal(err)
	}
	key := writeFixture("key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKey}))
	mimeTypes := writeFixture("mime.types", []byte("text/html html\napplication/json json\napplication/zip zip\n"))
	template, err := os.ReadFile("../deploy/apache/share-errors.conf")
	if err != nil {
		t.Fatal(err)
	}
	config := []string{
		fmt.Sprintf("ServerRoot %q", dir), "DefaultRuntimeDir .", "PidFile httpd.pid",
		"Listen " + addr, "ServerName 127.0.0.1", fmt.Sprintf("Define APACHE_LOG_DIR %q", dir),
		fmt.Sprintf("ErrorLog %q", filepath.Join(dir, "apache-error.log")), fmt.Sprintf("DocumentRoot %q", dir),
	}
	for _, name := range []string{"mpm_event", "unixd", "authz_core", "log_config", "mime", "alias", "proxy", "proxy_http", "ssl", "http2"} {
		// Debian compiles unixd and log_config in. macOS supplies them as modules.
		config = append(config, fmt.Sprintf("<IfModule !%s_module>\nLoadModule %s_module %q\n</IfModule>",
			name, name, filepath.Join(modules, "mod_"+name+".so")))
	}
	config = append(config,
		fmt.Sprintf(`User "#%d"`, os.Getuid()), fmt.Sprintf(`Group "#%d"`, os.Getgid()), fmt.Sprintf("TypesConfig %q", mimeTypes),
		"<VirtualHost "+addr+">", "Protocols h2 http/1.1", "SSLEngine on", "SSLProtocol -all +TLSv1.2",
		fmt.Sprintf("SSLCertificateFile %q", cert), fmt.Sprintf("SSLCertificateKeyFile %q", key),
		strings.ReplaceAll(string(template), "/var/www/errors", dir),
		"ProxyPass / "+origin+"/", "ProxyPassReverse / "+origin+"/", "</VirtualHost>",
	)
	configPath := writeFixture("httpd.conf", []byte(strings.Join(config, "\n")+"\n"))
	if output, err := exec.CommandContext(t.Context(), apache, "-t", "-f", configPath).CombinedOutput(); err != nil {
		t.Fatalf("Apache rejected its test configuration: %v\n%s", err, output)
	}
	console, err := os.Create(filepath.Join(dir, "console.log"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = console.Close() })
	proc := exec.Command(apache, "-X", "-f", configPath)
	proc.Stdout, proc.Stderr = console, console
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	if err := proc.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proc.Process.Kill(); _ = proc.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return "https://" + addr, roots
		}
		time.Sleep(25 * time.Millisecond)
	}
	output, _ := os.ReadFile(console.Name())
	errorLog, _ := os.ReadFile(filepath.Join(dir, "error.share.jeanphilippe.io.log"))
	t.Fatalf("Apache did not listen on its loopback address\n%s\n%s", output, errorLog)
	return "", nil
}
