package routes

import (
	"github.com/jeanphilippe-mh/Okuru/controllers"
	"github.com/labstack/echo/v4"
)

func Index(e *echo.Echo) {
	e.GET("/", controllers.Index)
	e.POST("/", controllers.AddIndex)
	e.GET("/privacy-policy", controllers.PrivacyIndex)
	e.GET("/:password_key", controllers.ReadIndex)
	e.GET("/csrf-token", controllers.GetCSRFToken)
	e.POST("/:password_key", controllers.RevealPassword)
	e.GET("/remove/:password_key", controllers.DeleteIndex)
}
