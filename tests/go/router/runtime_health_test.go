package router

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jeanphilippe-mh/Okuru/routes"
)

type cachedHealth struct{ ready bool }

func (s *cachedHealth) Ready() bool { return s.ready }

func TestRuntimeHealthThroughEcho(t *testing.T) {
	e := New()
	state := new(cachedHealth)
	routes.RuntimeHealth(e, state)
	// Exhaust the normal application's concurrency slots. Health requests
	// remain lightweight and do not borrow these slots or set CSRF cookies.
	for i := 0; i < cap(requestSlots); i++ {
		requestSlots <- struct{}{}
	}
	defer func() {
		for i := 0; i < cap(requestSlots); i++ {
			<-requestSlots
		}
	}()
	for _, tc := range []struct {
		method, path string
		ready        bool
		wantCode     int
		wantStatus   string
	}{
		{"GET", "/ping", false, 200, "alive"}, {"HEAD", "/ping", false, 200, ""},
		{"GET", "/p%69ng", false, 200, "alive"},
		{"GET", "/ready", false, 503, "unavailable"}, {"HEAD", "/ready", false, 503, ""},
		{"GET", "/ready", true, 200, "ready"}, {"GET", "/ping", true, 200, "alive"},
		{"POST", "/ping", true, 405, ""},
	} {
		state.ready = tc.ready
		rec := httptest.NewRecorder()
		e.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != tc.wantCode || rec.Header().Get("Cache-Control") != "no-store" || len(rec.Result().Cookies()) != 0 {
			t.Fatalf("%s %s: status=%d headers=%v", tc.method, tc.path, rec.Code, rec.Header())
		}
		if tc.method == http.MethodGet {
			var result map[string]string
			if !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") || json.Unmarshal(rec.Body.Bytes(), &result) != nil || len(result) != 1 || result["status"] != tc.wantStatus {
				t.Fatalf("invalid probe response: %s", rec.Body.String())
			}
		} else if rec.Body.Len() != 0 {
			t.Fatal("unexpected response body")
		}
	}
}

func TestRuntimeStorageClassifiesArchiveRequests(t *testing.T) {
	for _, c := range []struct {
		method, path string
		needs        bool
	}{
		{"POST", "/file", true}, {"POST", "/file/", true}, {"POST", "/api/v2/files/direct", true},
		{"POST", "/api/v2/uploads", true}, {"POST", "/api/v2/files", true}, {"PATCH", "/api/v2/uploads/id/files/1", true},
		{"POST", "/api/v2/uploads/id/complete/", true},
		{"GET", "/file/id", false}, {"POST", "/file/id", false}, {"POST", "/file/remove/id", false}, {"DELETE", "/file/id", false},
		{"DELETE", "/api/v2/uploads/id", false}, {"HEAD", "/api/v2/uploads/id/files/1", false}, {"POST", "/file/confirmation", false},
		{"POST", "/api/v2/secrets", false}, {"GET", "/ready", false}, {"GET", "/ping", false},
	} {
		if got := NeedsArchiveCapacity(httptest.NewRequest(c.method, c.path, nil)); got != c.needs {
			t.Fatalf("%s %s requires archive space=%t", c.method, c.path, got)
		}
	}
}
