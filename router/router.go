package router

import (
	"errors"
	"github.com/jeanphilippe-mh/Okuru/routes"
	"github.com/jeanphilippe-mh/Okuru/utils"
	log "github.com/sirupsen/logrus"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/flosch/pongo2"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"gopkg.in/go-playground/validator.v9"
)

type (
	CustomValidator struct {
		validator *validator.Validate
	}
	Renderer struct {
		Debug bool
	}
)

func (cv *CustomValidator) Validate(i interface{}) error {
	return cv.validator.Struct(i)
}

func (r Renderer) Render(_ *echo.Context, w io.Writer, name string, data interface{}) error {
	var ctx pongo2.Context
	var t *pongo2.Template
	var err error

	ex, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	loader, err := pongo2.NewLocalFileSystemLoader(filepath.Dir(ex) + "/views")
	if err != nil {
		log.Fatal(err)
	}

	templates := pongo2.NewSet("request", loader)

	if data != nil {
		var ok bool
		ctx, ok = data.(pongo2.Context)

		if !ok {
			return errors.New("No pongo2.Context data was passed")
		}
	}

	if r.Debug {
		t, err = templates.FromFile(name)
	} else {
		t, err = templates.FromCache(name)
	}

	// Add some static values
	ctx["version_number"] = "v0.0.1-beta"

	if err != nil {
		return err
	}

	// return t.ExecuteWriter(ctx, w)
	result := t.ExecuteWriter(ctx, w)
	log.Debugf("%+v\n", result)
	return result
}

func New() *echo.Echo {
	return NewWithTimeouts(defaultIOIdleTimeout, 2*time.Hour, 2*time.Hour)
}

// NewWithTimeouts applies idle and absolute limits to each transfer. The
// server-level timeouts are configured separately as a transport backstop.
func NewWithTimeouts(idleTimeout, readTimeout, writeTimeout time.Duration) *echo.Echo {
	if idleTimeout <= 0 {
		idleTimeout = defaultIOIdleTimeout
	}
	if readTimeout <= 0 {
		readTimeout = 2 * time.Hour
	}
	if writeTimeout <= 0 {
		writeTimeout = 2 * time.Hour
	}
	renderer := Renderer{
		Debug: true,
	}
	e := echo.New()
	e.Pre(shortLinkHeaders)
	e.Pre(removeTrailingSlash)
	e.Renderer = renderer
	e.Validator = &CustomValidator{validator: validator.New()}

	// Route => Handler
	ex, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}

	// Protect parsing, including CSRF form extraction, before entering middleware.
	e.Use(requestLimits(idleTimeout, readTimeout, writeTimeout))

	// Middleware BodyLimit
	// Set the request body size limit to 1024MB to reflect ModSecurity - OWASP (WAF) setup.
	e.Use(middleware.BodyLimit(maxUploadBodyBytes))

	// Middleware RequestLogger (for Echo 4.14+)
	slogHandler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	slogger := slog.New(slogHandler)

	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		HandleError: true,

		LogLatency:       true,
		LogRemoteIP:      true,
		LogHost:          true,
		LogMethod:        true,
		LogURI:           false,
		LogStatus:        true,
		LogContentLength: true,
		LogResponseSize:  true,
		LogUserAgent:     true,

		LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error {
			errMsg := ""
			if v.Error != nil {
				errMsg = safeLogError(v.Error)
			}

			slogger.LogAttrs(c.Request().Context(), slog.LevelInfo, "http_request",
				slog.String("time", v.StartTime.UTC().Format(time.RFC3339Nano)),
				slog.String("remote_ip", boundedLogText(v.RemoteIP, maxLoggedRemoteIPBytes)),
				slog.String("host", boundedLogText(v.Host, maxLoggedHostBytes)),
				slog.String("method", boundedLogText(v.Method, maxLoggedMethodBytes)),
				slog.String("route", safeLogRoute(c)),
				slog.Int("status", v.Status),
				slog.String("error", errMsg),
				slog.String("latency_human", v.Latency.String()),
				slog.String("bytes_in", boundedLogText(v.ContentLength, maxLoggedLengthBytes)),
				slog.Int64("bytes_out", v.ResponseSize),
				slog.String("user_agent", boundedLogText(v.UserAgent, maxLoggedUserAgentBytes)),
			)
			return nil
		},
	}))

	// Parse multipart file bodies without writing plaintext, before CSRF's
	// FormValue lookup can invoke the standard multipart parser.
	e.Use(secureMultipart)

	// Middleware CSRF
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLength:    32,
		TokenLookup:    "form:_csrf,header:X-CSRF-Token",
		CookieSecure:   true,
		CookieHTTPOnly: true,
		CookieSameSite: http.SameSiteStrictMode,
		// Echo v4 validated tokens for same-site, cross-origin requests.
		// Keep that behavior without bypassing the token check or allowing
		// cross-site and unrecognized Fetch Metadata values.
		AllowSecFetchSiteFunc: func(c *echo.Context) (bool, error) {
			if c.Request().Header.Get(echo.HeaderSecFetchSite) == "same-site" {
				return false, nil
			}
			return false, echo.NewHTTPError(http.StatusForbidden, "cross-site request blocked by CSRF")
		},
	}))

	// Middleware Static
	publicfolder := filepath.Dir(ex) + "/public"
	e.Use(publicAssets(publicfolder))

	// Creating groups
	apiGroup := e.Group("/api/v1")
	fileGroup := e.Group("/file")

	routes.Index(e)
	routes.Password(apiGroup)
	routes.File(fileGroup)

	return e
}

// publicAssets keeps filesystem lookup anchored to the executable's public
// directory, independently of the process working directory.
func publicAssets(publicfolder string) echo.MiddlewareFunc {
	return middleware.StaticWithConfig(middleware.StaticConfig{
		// API errors must not enter the HTML5 fallback or become filesystem errors.
		Skipper: func(c *echo.Context) bool {
			path := c.Request().URL.Path
			return path == "/api" || strings.HasPrefix(path, "/api/") || utils.IsRootShortLinkPath(path)
		},
		// Echo v5's default filesystem is rooted at the working directory.
		// Okuru serves assets next to the executable, which can be elsewhere.
		Filesystem: os.DirFS(publicfolder),
		Root:       ".",
		HTML5:      true,
		Browse:     false,
	})
}
