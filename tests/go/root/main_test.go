package main

import (
	"testing"
	"time"
)

func TestHTTPTimeoutDefaultsAndOverrides(t *testing.T) {
	for _, name := range []string{"OKURU_HTTP_READ_TIMEOUT", "OKURU_HTTP_WRITE_TIMEOUT", "OKURU_HTTP_IDLE_TIMEOUT", "OKURU_HTTP_TRANSFER_IDLE_TIMEOUT"} {
		t.Setenv(name, "")
	}
	got, err := loadHTTPTimeouts()
	if err != nil {
		t.Fatal(err)
	}
	if got.read != 2*time.Hour || got.write != 2*time.Hour || got.idle != 90*time.Second || got.transferIdle != 2*time.Minute {
		t.Fatalf("unexpected timeout defaults: %+v", got)
	}
	t.Setenv("OKURU_HTTP_READ_TIMEOUT", "3h")
	got, err = loadHTTPTimeouts()
	if err != nil || got.read != 3*time.Hour {
		t.Fatalf("override ignored: %+v %v", got, err)
	}
	for _, invalid := range []string{"0", "-1s", "bad"} {
		t.Setenv("OKURU_HTTP_READ_TIMEOUT", invalid)
		if _, err := loadHTTPTimeouts(); err == nil {
			t.Fatalf("accepted unsafe timeout %q", invalid)
		}
	}
}
