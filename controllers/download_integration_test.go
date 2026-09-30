package controllers

import (
	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloadArchiveIntegration(t *testing.T) {
	addr := os.Getenv("OKURU_TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("Redis required")
	}
	oldHost, oldPort, oldDB, oldPassword, oldPrefix, oldFolder := REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX, FILEFOLDER
	t.Cleanup(func() {
		REDIS_HOST, REDIS_PORT, REDIS_DB, REDIS_PASSWORD, REDIS_PREFIX, FILEFOLDER = oldHost, oldPort, oldDB, oldPassword, oldPrefix, oldFolder
	})
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatal(err)
	}
	REDIS_HOST = host
	REDIS_PORT = port
	REDIS_DB = "0"
	REDIS_PASSWORD = ""
	REDIS_PREFIX = "integration_download_"
	FILEFOLDER = t.TempDir()
	for _, protected := range []bool{false, true} {
		token, err := SetFile("password", 60, 1, true, protected, "")
		if err != nil {
			t.Fatal(err)
		}
		name, e := archiveNameFromToken(token)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(FILEFOLDER, name), []byte("archive-test"), 0600); e != nil {
			t.Fatal(e)
		}
		echoServer := echo.New()
		echoServer.Renderer = testRenderer{}
		req := httptest.NewRequest("POST", "/file/"+token, strings.NewReader(url.Values{"password": {"password"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		c := echoServer.NewContext(req, rec)
		c.SetParamNames("file_key")
		c.SetParamValues(token)
		if e = DownloadFile(c); e != nil {
			t.Fatal(e)
		}
		if rec.Code != 200 || rec.Body.String() != "archive-test" {
			t.Fatalf("protected=%v status=%d body=%q", protected, rec.Code, rec.Body.String())
		}
	}
}
