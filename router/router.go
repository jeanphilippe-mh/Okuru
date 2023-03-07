package router

import (
	"net/http"
	"errors"
	"github.com/jeanphilippe-mh/Okuru/routes"
	log "github.com/sirupsen/logrus"
	"io"
	"os"
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

	// Middleware Logger
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `{"time":"${time_rfc3339_nano}","remote_ip":"${remote_ip}","host":"${host}",` +
			`"method":"${method}","uri":"${uri}","status":${status},"error":"${error}",` +
			`"latency_human":"${latency_human}","bytes_in":${bytes_in},` +
			`"bytes_out":${bytes_out}` +
			`"user_agent":${user_agent}}` + "\n",
	}))

	// Middleware CORS
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowMethods: []string{echo.GET, echo.HEAD, echo.OPTIONS, echo.POST, echo.DELETE},
	}))
	
	// Middleware CSRF
	e.Use(middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup:	"form:csrf_token",
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
