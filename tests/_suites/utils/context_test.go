package utils

import (
	"sync"
	"testing"
)

func TestRequestContextsAreIsolated(t *testing.T) {
	first, second := NewDataContext(), NewDataContext()
	first["csrfToken"] = "first-token"
	first["passwordLink"] = "first-secret"
	if _, ok := second["csrfToken"]; ok {
		t.Fatal("CSRF token leaked")
	}
	if _, ok := second["passwordLink"]; ok {
		t.Fatal("secret link leaked")
	}
	if second["APP_NAME"] != APP_NAME {
		t.Fatal("application settings missing")
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := NewDataContext()
			data["csrfToken"] = "request-token"
			delete(data, "APP_NAME")
		}()
	}
	wg.Wait()
	if NewDataContext()["APP_NAME"] != APP_NAME {
		t.Fatal("base context mutated")
	}
}
