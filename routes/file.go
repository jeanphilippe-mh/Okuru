package routes

import (
	"github.com/jeanphilippe-mh/Okuru/controllers"
	"github.com/labstack/echo/v4"
)

func File(g *echo.Group) {
	g.GET("", controllers.IndexFile)
	e.GET("/400.html", controllers.Error400File)
	e.GET("/403.html", controllers.Error403File)
	e.GET("/404.html", controllers.Error404File)
	e.GET("/413.html", controllers.Error413File)
	e.GET("/500.html", controllers.Error500File)
	g.GET("/remove/:file_key", controllers.DeleteFile)
	g.GET("/:file_key", controllers.ReadFile)
	g.POST("/:file_key", controllers.DownloadFile)
	g.POST("", controllers.AddFile)
	g.DELETE("/:file_key", controllers.DeleteFile)
}
