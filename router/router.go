package router

import (
	"net/http"
	"errors"
	"github.com/jeanphilippe-mh/Okuru/routes"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
	"log/slog"
	"time"
	"path/filepath"

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
	err = pongo2.DefaultLoader.SetBaseDir(filepath.Dir(ex) + "/views")
	if err != nil {
		log.Fatal(err)
	}

	if data != nil {
		var ok bool
		ctx, ok = data.(pongo2.Context)

		if !ok {
			return errors.New("no pongo2.Context data was passed")
		}
	}

	if r.Debug {
		t, err = pongo2.FromFile(name)
	} else {
		t, err = pongo2.FromCache(name)
	}

	// Add some static values
	ctx["version_number"] = "v0.0.1-beta"

	if err != nil {
		return err
	}

	// return t.ExecuteWriter(ctx, w)
	result := t.ExecuteWriter(ctx, w)
	log.Debug("%+v\n", result)
	return result
}

func New() *echo.Echo {
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

	// Middleware BodyLimit
	// Set the request body size limit to 1024MB to reflect ModSecurity - OWASP (WAF) setup.
	e.Use(middleware.BodyLimit("1024M"))
	
	// Middleware RequestLogger (for Echo 4.14+)
	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	var mu sync.Mutex

	e.Use(middleware.RequestLoggerWithConfig(middleware.RequestLoggerConfig{
	HandleError: true,

	LogLatency:       true,
	LogRemoteIP:      true,
	LogHost:          true,
	LogMethod:        true,
	LogURI:           true,
	LogStatus:        true,
	LogError:         true,
	LogContentLength: true,
	LogResponseSize:  true,
	LogUserAgent:     true,

	LogValuesFunc: func(c echo.Context, v middleware.RequestLoggerValues) error {
		errMsg := ""
		if v.Error != nil {
			errMsg = v.Error.Error()
		}

		var bytesIn int64
		if v.ContentLength != "" {
			if n, err := strconv.ParseInt(v.ContentLength, 10, 64); err == nil && n >= 0 {
				bytesIn = n
			}
		}

		line := map[string]any{
			"time":          v.StartTime.UTC().Format(time.RFC3339Nano),
			"remote_ip":     v.RemoteIP,
			"host":          v.Host,
			"method":        v.Method,
			"uri":           v.URI,
			"status":        v.Status,
			"error":         errMsg,
			"latency_human": v.Latency.String(),
			"bytes_in":      bytesIn,
			"bytes_out":     v.ResponseSize,
			"user_agent":    v.UserAgent,
		}

		mu.Lock()
		defer mu.Unlock()
		return enc.Encode(line)
	},
	}))

	// Middleware CORS
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowMethods: []string{echo.GET, echo.HEAD, echo.OPTIONS, echo.POST, echo.DELETE},
	}))
	
	// Middleware CSRF
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLength:	32,
		TokenLookup:    "form:_csrf",
		CookieSecure:	true,
		CookieHTTPOnly:	true,
		CookieSameSite:	http.SameSiteStrictMode,
	}))

	// Middleware Static
	publicfolder := filepath.Dir(ex) + "/public"
	e.Use(middleware.StaticWithConfig(middleware.StaticConfig{
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
