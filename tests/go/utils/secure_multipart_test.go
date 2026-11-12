package utils

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func secureTestRequest(t *testing.T, payload []byte) *http.Request {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("files", "secret-name.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(payload); err != nil {
		t.Fatal(err)
	}
	// A real browser puts the file before the password in the existing form.
	if err := w.WriteField("password", "test-password"); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteField("_csrf", "test-csrf"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/file", &body)
	r.Header.Set("Content-Type", w.FormDataContentType())
	return r
}

func TestSecureMultipartStoresOnlyCiphertext(t *testing.T) {
	root := t.TempDir()
	otherTemp := t.TempDir()
	t.Setenv("TMPDIR", otherTemp)
	payload := bytes.Repeat([]byte("PLAINTEXT-SENSITIVE-MARKER-"), 8000)
	r := secureTestRequest(t, payload)
	form, err := ParseSecureMultipart(r, root, 1<<20, 100)
	if err != nil {
		t.Fatal(err)
	}
	defer form.Close()
	if got := r.FormValue("password"); got != "test-password" {
		t.Fatalf("password field = %q", got)
	}
	if got := r.FormValue("_csrf"); got != "test-csrf" {
		t.Fatalf("csrf field = %q", got)
	}
	if len(form.Files) != 1 || form.Files[0].Size != int64(len(payload)) {
		t.Fatal("file metadata was lost")
	}
	files, err := os.ReadDir(form.stage.Path)
	if err != nil || len(files) != 2 {
		t.Fatalf("staging files: %v %v", files, err)
	}
	staged, err := os.ReadFile(form.Files[0].path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(staged, payload[:100]) || bytes.Contains(staged, []byte("secret-name.txt")) {
		t.Fatal("plaintext leaked to staging")
	}
	info, err := os.Stat(form.Files[0].path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("permissions: %v %v", info, err)
	}
	in, err := form.Files[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	actual, err := io.ReadAll(in)
	_ = in.Close()
	if err != nil || !bytes.Equal(actual, payload) {
		t.Fatalf("decryption failed: %v", err)
	}
	if files, err := os.ReadDir(otherTemp); err != nil || len(files) != 0 {
		t.Fatal("system temporary directory received spill files")
	}
	if err := form.Close(); err != nil {
		t.Fatal(err)
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("staging not removed: %v %v", entries, err)
	}
}

func TestSecureMultipartCloseRequiresReadersToClose(t *testing.T) {
	root := t.TempDir()
	payload := []byte("reader keeps encrypted staging alive")
	r := secureTestRequest(t, payload)
	form, err := ParseSecureMultipart(r, root, 1<<20, 100)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := form.Files[0].Open()
	if err != nil {
		t.Fatal(err)
	}
	if err := form.Close(); err == nil {
		_ = reader.Close()
		t.Fatal("closed multipart form while reader was open")
	}
	if _, err := os.Stat(form.Files[0].path); err != nil {
		_ = reader.Close()
		t.Fatalf("staging was mutated before reader closed: %v", err)
	}
	actual, err := io.ReadAll(reader)
	if err != nil || !bytes.Equal(actual, payload) {
		_ = reader.Close()
		t.Fatalf("open reader stopped working: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("reader close is not idempotent: %v", err)
	}
	if err := form.Close(); err != nil {
		t.Fatalf("cleanup did not succeed after reader closed: %v", err)
	}
	if _, err := form.Files[0].Open(); err == nil {
		t.Fatal("closed multipart form allowed another reader")
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("staging not removed: %v %v", entries, err)
	}
}

func TestSecureMultipartFailsClosedAndCleansUp(t *testing.T) {
	for _, max := range []int64{1, 20} {
		root := t.TempDir()
		r := secureTestRequest(t, bytes.Repeat([]byte("x"), 64))
		if _, err := ParseSecureMultipart(r, root, max, 100); err == nil {
			t.Fatal("oversized file accepted")
		}
		if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
			t.Fatalf("failed upload left staging: %v %v", entries, err)
		}
	}
	root := t.TempDir()
	r := secureTestRequest(t, []byte("x"))
	if err := r.ParseMultipartForm(1024); err != nil {
		t.Fatal(err)
	}
	defer r.MultipartForm.RemoveAll()
	if _, err := ParseSecureMultipart(r, root, 1024, 100); err == nil {
		t.Fatal("already parsed multipart accepted")
	}
}

func TestSecureMultipartRejectsInvalidNamesBeforeReadingContent(t *testing.T) {
	for name, header := range map[string]string{
		"invalid": "--boundary\r\nContent-Disposition: form-data; name=\"files\"; filename=\"bad?.txt\"\r\n\r\n",
		"duplicate": "--boundary\r\nContent-Disposition: form-data; name=\"files\"; filename=\"FILE.txt\"\r\n\r\nfirst\r\n" +
			"--boundary\r\nContent-Disposition: form-data; name=\"files\"; filename=\"file.TXT\"\r\n\r\n",
		"unicode duplicate": "--boundary\r\nContent-Disposition: form-data; name=\"files\"; filename=\"É.txt\"\r\n\r\nfirst\r\n" +
			"--boundary\r\nContent-Disposition: form-data; name=\"files\"; filename=\"é.txt\"\r\n\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			body := io.MultiReader(strings.NewReader(header), multipartBlockingTail{release: release})
			r := httptest.NewRequest(http.MethodPost, "/file", body)
			r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
			result := make(chan error, 1)
			go func() {
				_, err := ParseSecureMultipart(r, root, 1024, 100)
				result <- err
			}()
			select {
			case err := <-result:
				if !errors.Is(err, ErrSecureMultipartFilename) {
					t.Fatalf("expected filename error, got %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("parser read or drained the rejected file body")
			}
			if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
				t.Fatalf("rejected upload left staging: %v %v", entries, err)
			}
		})
	}
}

type multipartBlockingTail struct{ release <-chan struct{} }

func (b multipartBlockingTail) Read([]byte) (int, error) { <-b.release; return 0, io.EOF }

func TestSecureMultipartOversizeDoesNotDrainBlockedInput(t *testing.T) {
	for _, kind := range []string{"field", "file"} {
		t.Run(kind, func(t *testing.T) {
			var header string
			limit := int64(65536)
			payloadSize := MaxSecretBytes + 8192
			if kind == "field" {
				header = "--boundary\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\n"
			} else {
				header = "--boundary\r\nContent-Disposition: form-data; name=\"files\"; filename=\"f.txt\"\r\nContent-Type: application/octet-stream\r\n\r\n"
				payloadSize = int(limit) + 8192
			}
			prefix := header + strings.Repeat("x", payloadSize)
			release := make(chan struct{})
			defer close(release)
			body := io.MultiReader(strings.NewReader(prefix), multipartBlockingTail{release})
			r := httptest.NewRequest("POST", "/file", body)
			r.Header.Set("Content-Type", "multipart/form-data; boundary=boundary")
			result := make(chan error, 1)
			root := t.TempDir()
			go func() { _, err := ParseSecureMultipart(r, root, limit, 100); result <- err }()
			select {
			case err := <-result:
				if !errors.Is(err, ErrSecureMultipartTooLarge) {
					t.Fatalf("unexpected error: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("oversized input was drained and blocked")
			}
		})
	}
}

// Child exits without deferred cleanup, exercising the disk state after an
// abrupt process termination rather than just the normal cleanup path.
func TestSecureMultipartCrashLeavesOnlyCiphertext(t *testing.T) {
	const marker = "CRASH-PRIVATE-MULTIPART-CONTENT"
	if root := os.Getenv("OKURU_CRASH_TEST_DIR"); root != "" {
		r := secureTestRequest(t, bytes.Repeat([]byte(marker), 10000))
		if _, err := ParseSecureMultipart(r, root, 1<<20, 100); err != nil {
			os.Exit(2)
		}
		os.Exit(0)
	}
	root := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSecureMultipartCrashLeavesOnlyCiphertext$")
	cmd.Env = append(os.Environ(), "OKURU_CRASH_TEST_DIR="+root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("child failed: %v %s", err, out)
	}
	var count int
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		count++
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(marker)) || strings.Contains(path, "secret-name") {
			t.Fatal("crash left plaintext staging")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("crash test did not leave staged ciphertext")
	}
}

func TestSecureMultipartKilledDuringWrite(t *testing.T) {
	const marker = "KILLED-WRITE-PRIVATE-CONTENT"
	if root := os.Getenv("OKURU_KILL_TEST_DIR"); root != "" {
		pr, pw := io.Pipe()
		mw := multipart.NewWriter(pw)
		go func() {
			part, err := mw.CreateFormFile("files", "sensitive-name.txt")
			if err != nil {
				os.Exit(2)
			}
			if _, err := part.Write(bytes.Repeat([]byte(marker), 10000)); err != nil {
				os.Exit(3)
			}
			fmt.Println("PART_WRITTEN")
			select {}
		}()
		r := httptest.NewRequest("POST", "/file", pr)
		r.Header.Set("Content-Type", mw.FormDataContentType())
		_, _ = ParseSecureMultipart(r, root, 1<<20, 100)
		os.Exit(4)
	}
	root := t.TempDir()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSecureMultipartKilledDuringWrite$")
	cmd.Env = append(os.Environ(), "OKURU_KILL_TEST_DIR="+root)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	ready := make(chan string, 1)
	go func() { line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
	select {
	case line := <-ready:
		if line != "PART_WRITTEN\n" {
			t.Fatalf("child did not write: %q %s", line, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child did not reach partial write")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	var files int
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		files++
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(data, []byte(marker)) || strings.Contains(path, "sensitive-name") {
			t.Fatal("SIGKILL left plaintext")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("SIGKILL test did not leave partially written ciphertext")
	}
}
