package utils

import (
	"bytes"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"
)

func TestEchoStartupBannerRestoresOriginalArtAndSeparators(t *testing.T) {
	banner := EchoStartupBanner()
	want := []string{
		"",
		"---------------------------------------------",
		"",
		"   ____    __",
		"  / __/___/ /  ___",
		` / _// __/ _ \/ _ \`,
		`/___/\__/_//_/\___/ ` + echo.Version,
		"High performance, minimalist Go web framework",
		"https://echo.labstack.com",
		"____________________________________O/_______",
		`                                    O\`,
		"",
		"---------------------------------------------",
		"",
	}
	lines := strings.Split(strings.TrimSuffix(banner, "\n"), "\n")
	if len(lines) != len(want) {
		t.Fatalf("banner has %d lines, want %d", len(lines), len(want))
	}
	for i := range lines {
		if lines[i] != want[i] {
			t.Errorf("banner line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}

func TestEchoStartupBannerThroughSupervisorNormalizers(t *testing.T) {
	banner := EchoStartupBanner()
	if got := EchoStartupOutput(false); got != banner {
		t.Fatalf("direct startup did not return the original banner: %q", got)
	}
	frame := EchoStartupOutput(true)
	if frame != echoBannerControl || frame == banner {
		t.Fatal("supervised startup did not produce the internal control frame")
	}
	var trusted bytes.Buffer
	if err := NormalizeProcessOutput(strings.NewReader(frame), &trusted); err != nil {
		t.Fatal(err)
	}
	if trusted.String() != banner {
		t.Fatalf("trusted stdout changed the banner: %q", trusted.String())
	}
	if strings.Contains(trusted.String(), "[INTERNAL]") || strings.Contains(trusted.String(), "[INFO]") {
		t.Fatal("internal marker or log prefixes leaked into banner")
	}
	var untrusted bytes.Buffer
	if err := NormalizeUntrustedProcessOutput(strings.NewReader(frame+banner), &untrusted); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(untrusted.String(), "\n"), "\n") {
		if !strings.HasPrefix(line, "[ERROR] {") || !strings.Contains(line, `"event":"process.output"`) {
			t.Fatalf("stderr was admitted as a trusted banner line: %q", line)
		}
	}
	if strings.Contains(untrusted.String(), "\n"+banner) {
		t.Fatal("stderr impersonated the banner")
	}
}
