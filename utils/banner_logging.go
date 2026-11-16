package utils

import (
	"strings"

	"github.com/labstack/echo/v5"
)

// echoBannerLines is a fixed startup-only decoration, intentionally separate
// from the structured logs so Echo's original artwork remains unobstructed.
func echoBannerLines() []string {
	return []string{
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
}

// EchoStartupBanner returns Echo's original ASCII artwork with a blank spacer
// and separator on each side. A single write keeps its short lines together.
func EchoStartupBanner() string {
	return strings.Join(echoBannerLines(), "\n") + "\n"
}

// echoBannerControl is an internal stdout frame, not a log entry. The
// supervisor expands this exact frame to the fixed banner; stderr never does.
const echoBannerControl = "[INTERNAL] okuru.echo.banner.v1\n"

// EchoStartupOutput emits the internal frame for a supervised worker and the
// complete artwork when Okuru runs directly without a supervisor.
func EchoStartupOutput(supervised bool) string {
	if supervised {
		return echoBannerControl
	}
	return EchoStartupBanner()
}
