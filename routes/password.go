package routes

import (
	"github.com/jeanphilippe-mh/Okuru/controllers"
	"github.com/labstack/echo/v4"
)

func Password(g *echo.Group) {
	g.GET("", controllers.HelpPassword)
	g.HEAD("", controllers.HelpPassword)
	g.OPTIONS("", controllers.HelpPassword)
	g.GET("/", controllers.HelpPassword)
	g.HEAD("/", controllers.HelpPassword)
	g.OPTIONS("/", controllers.HelpPassword)
	g.GET("/:password_key", controllers.ReadPassword)
	g.POST("", controllers.CreatePassword)
	g.DELETE("/:password_key", controllers.DeletePassword)
}
