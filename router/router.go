package router

import (
	"errors"
	"github.com/jeanphilippe-mh/Okuru/routes"
	log "github.com/sirupsen/logrus"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/flosch/pongo2"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
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

func (r Renderer) Render(w io.Writer, name string, data interface{}, _ echo.Context) error {
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
	e.Pre(middleware.RemoveTrailingSlash())
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
	e.Use(middleware.BodyLimit("1024M"))

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
		LogError:         true,
		LogContentLength: true,
		LogResponseSize:  true,
		LogUserAgent:     true,

		LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
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
	}))

	// Middleware Static
	publicfolder := filepath.Dir(ex) + "/public"
	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
		// API errors must not enter the HTML5 fallback or become filesystem errors.
		Skipper: func(c echo.Context) bool {
			path := c.Request().URL.Path
			return path == "/api" || strings.HasPrefix(path, "/api/")
		},
		Root:   publicfolder,
		HTML5:  true,
		Browse: false,
	}))

	// Creating groups
	apiGroup := e.Group("/api/v1")
	fileGroup := e.Group("/file")

	routes.Index(e)
	routes.Password(apiGroup)
	routes.File(fileGroup)

	return e
}
