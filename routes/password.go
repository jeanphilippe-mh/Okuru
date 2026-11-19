package routes

import (
	"github.com/jeanphilippe-mh/Okuru/controllers"
	"github.com/labstack/echo/v5"
)

func Secrets(g *echo.Group) {
	g.Use(controllers.SecretAPIGuard)
	g.GET("/bootstrap", controllers.BootstrapSecretAPI)
	g.POST("", controllers.CreateSecretAPI)
	g.GET("/:token", controllers.ReadSecretAPI)
	g.DELETE("/:token", controllers.DeleteSecretAPI)
}
