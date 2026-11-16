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
	"strconv"
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
	e.Logger = slog.New(&echoLogHandler{})
	e.Pre(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			utils.AuditRequestID(c)
			return next(c)
		}
	})
	e.Pre(shortLinkHeaders)
	e.Pre(removeTrailingSlash)
	e.Renderer = renderer
	e.Validator = &CustomValidator{validator: validator.New()}

	// Route => Handler
	ex, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}

	// Observe bounded security signals before the request limits and CSRF
	// middleware, without storing request paths or blocking client traffic.
	e.Use(securityObservations(processSecurityObserver))

	// Capture rejected requests as well as successful ones. This middleware
	// does not read the request body; size and upload admission remain inside it.
	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
		HandleError: true,

		LogLatency:       true,
		LogHost:          true,
		LogMethod:        true,
		LogURI:           false,
		LogStatus:        true,
		LogContentLength: true,
		LogResponseSize:  true,
		LogUserAgent:     true,

		LogValuesFunc: func(c *echo.Context, v middleware.RequestLoggerValues) error {
			fields := utils.AuditRequestFields(c)
			fields["event"] = "http.request"
			fields["started_at"] = v.StartTime.UTC().Format(time.RFC3339Nano)
			fields["host"] = boundedLogText(v.Host, maxLoggedHostBytes)
			fields["status"] = v.Status
			fields["duration_ms"] = float64(v.Latency.Microseconds()) / 1000
			if length, ok := requestContentLength(v.ContentLength); ok {
				fields["request_content_length"] = length
			}
			fields["bytes_out"] = v.ResponseSize
			fields["user_agent"] = boundedLogText(v.UserAgent, maxLoggedUserAgentBytes)
			if v.Error != nil {
				fields["error"] = safeLogError(v.Error)
			}
			entry := log.WithFields(fields)
			switch {
			case v.Status >= 500:
				entry.Error("HTTP request completed")
			case v.Status >= 400:
				entry.Warn("HTTP request completed")
			default:
				entry.Info("HTTP request completed")
			}
			return nil
		},
	}))

	// Protect parsing, including CSRF form extraction, before entering middleware.
	e.Use(requestLimits(idleTimeout, readTimeout, writeTimeout))

	// Keep the established upload body limit before multipart and CSRF parsing.
	e.Use(middleware.BodyLimit(maxUploadBodyBytes))

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

// requestContentLength reports the declared Content-Length header, not bytes
// actually read. Unknown, malformed, negative and out-of-range values are
// omitted from the audit record.
func requestContentLength(raw string) (int64, bool) {
	if raw == "" || strings.Trim(raw, "0123456789") != "" {
		return 0, false
	}
	length, err := strconv.ParseInt(raw, 10, 64)
	return length, err == nil
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
