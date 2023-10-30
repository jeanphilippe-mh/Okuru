package routes

import (
	"github.com/jeanphilippe-mh/Okuru/controllers"
	"github.com/labstack/echo/v4"
)

func Index(e *echo.Echo) {
	e.GET("/", controllers.Index)
	e.POST("/", controllers.AddIndex)
	e.GET("/privacy-policy", controllers.PrivacyIndex)
	e.GET("/400.html", controllers.Error400Index)
	e.GET("/403.html", controllers.Error403Index)
	e.GET("/404.html", controllers.Error404Index)
	e.GET("/413.html", controllers.Error413Index)
	e.GET("/500.html", controllers.Error500Index)
	e.GET("/security.txt", controllers.SecurityIndex)
	e.GET("/:password_key", controllers.ReadIndex)
	e.POST("/:password_key", controllers.RevealPassword)
	e.GET("/remove/:password_key", controllers.DeleteIndex)
}
