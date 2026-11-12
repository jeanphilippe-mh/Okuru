//go:build darwin || linux

package router

import (
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
)

// Verify that admission can recover quota from a process that died while
// holding a staging lock, without needing to delete active staging folders.
func TestUploadAdmissionReclaimsAbandonedStaging(t *testing.T) {
	if root := os.Getenv("OKURU_ROUTER_STALE_TEST"); root != "" {
		stage, err := utils.CreateLockedStagingDir(root, ".okuru-multipart-")
		if err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(filepath.Join(stage.Path, "sample.age"), make([]byte, 2<<20), 0600); err != nil {
			os.Exit(3)
		}
		// Simulate process death: do not run stage.Close.
		os.Exit(0)
	}
	root := t.TempDir()
	child := exec.Command(os.Args[0], "-test.run=^TestUploadAdmissionReclaimsAbandonedStaging$")
	child.Env = append(os.Environ(), "OKURU_ROUTER_STALE_TEST="+root)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("staging subprocess failed: %v: %s", err, output)
	}
	oldFolder := utils.FILEFOLDER
	utils.FILEFOLDER = root
	t.Cleanup(func() { utils.FILEFOLDER = oldFolder })
	t.Setenv("OKURU_STORAGE_QUOTA_BYTES", "3145728")
	e := echo.New()
	e.Use(requestLimits(time.Minute, time.Hour, time.Hour))
	e.POST("/file", func(c echo.Context) error { return c.NoContent(http.StatusOK) })
	req := httptest.NewRequest(http.MethodPost, "/file", strings.NewReader("body"))
	req.Header.Set(echo.HeaderContentType, "multipart/form-data; boundary=test")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("admission after abandoned staging returned %d", rec.Code)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 1 || entries[0].Name() != ".okuru-quota" || !entries[0].IsDir() {
		t.Fatalf("abandoned staging not removed: %v, %v", entries, err)
	}
}
