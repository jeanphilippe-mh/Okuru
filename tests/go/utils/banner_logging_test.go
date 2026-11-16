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
		"[INFO] ",
		"[INFO] ---------------------------------------------",
		"[INFO] ",
		"[INFO]    ____    __",
		"[INFO]   / __/___/ /  ___",
		`[INFO]  / _// __/ _ \/ _ \`,
		`[INFO] /___/\__/_//_/\___/ ` + echo.Version,
		"[INFO] High performance, minimalist Go web framework",
		"[INFO] https://echo.labstack.com",
		"[INFO] ____________________________________O/_______",
		`[INFO]                                     O\`,
		"[INFO] ",
		"[INFO] ---------------------------------------------",
		"[INFO] ",
	}
	lines := strings.Split(strings.TrimSuffix(banner, "\n"), "\n")
	if len(lines) != len(want) {
		t.Fatalf("banner has %d lines, want %d", len(lines), len(want))
	}
	for i := range lines {
		if lines[i] != want[i] {
			t.Errorf("banner line %d = %q, want %q", i, lines[i], want[i])
		}
		if !IsEchoBannerLine([]byte(lines[i] + "\n")) {
			t.Errorf("banner line %d was not recognised", i)
		}
	}
	for _, forged := range []string{
		"[INFO] arbitrary",
		"[INFO] [ACTION] user supplied event",
		"[INFO] --------------------------------------------- suffix",
		`[INFO] /___/\__/_//_/\___/ forged-version`,
	} {
		if IsEchoBannerLine([]byte(forged + "\n")) {
			t.Errorf("unrecognised line was accepted as banner: %q", forged)
		}
	}
}

func TestEchoStartupBannerThroughSupervisorNormalizers(t *testing.T) {
	banner := EchoStartupBanner()
	var trusted bytes.Buffer
	if err := NormalizeProcessOutput(strings.NewReader(banner), &trusted); err != nil {
		t.Fatal(err)
	}
	if trusted.String() != banner {
		t.Fatalf("trusted stdout changed the banner: %q", trusted.String())
	}
	var untrusted bytes.Buffer
	if err := NormalizeUntrustedProcessOutput(strings.NewReader(banner), &untrusted); err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSuffix(untrusted.String(), "\n"), "\n") {
		if !strings.HasPrefix(line, "[ERROR] {") || !strings.Contains(line, `"event":"process.output"`) {
			t.Fatalf("stderr was admitted as a trusted banner line: %q", line)
		}
	}
}
