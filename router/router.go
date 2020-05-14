package router

import (
	"errors"
	"github.com/jeanphilippe-mh/Okuru/routes"
	log "github.com/sirupsen/logrus"
	"os"
	"path/filepath"

	"github.com/flosch/pongo2"
	"github.com/labstack/echo"
	"github.com/labstack/echo/v4/middleware"
	"gopkg.in/go-playground/validator.v9"
	"io"
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

func (r Renderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
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

	//return t.ExecuteWriter(ctx, w)
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
	// Middleware
	e.Use(middleware.LoggerWithConfig(middleware.LoggerConfig{
		Format: `{"time":"${time_rfc3339_nano}","remote_ip":"${remote_ip}","host":"${host}",` +
			`"method":"${method}","uri":"${uri}","status":${status},"error":"${error}",` +
			`"latency_human":"${latency_human}","bytes_in":${bytes_in},` +
			`"bytes_out":${bytes_out}` +
			`"user_agent":${user_agent}}` + "\n",
	}))
	//CORS
	e.Use(middleware.CORSWithConfig(middleware.CORSConfig{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{echo.GET, echo.HEAD, echo.OPTIONS, echo.POST, echo.DELETE},
	}))

	// Creating groups
	apiGroup := e.Group("/api/v1")
	fileGroup := e.Group("/file")

	//Route => handler
	ex, err := os.Executable()
	if err != nil {
		log.Fatal(err)
	}
	e.Static("/", filepath.Dir(ex)+"/public") //this need to be before routing
	routes.Index(e)
	routes.Password(apiGroup)
	routes.File(fileGroup)

	return e
}
