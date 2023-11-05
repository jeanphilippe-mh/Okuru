package routes

import (
	"github.com/jeanphilippe-mh/Okuru/controllers"
	"github.com/labstack/echo/v4"
)

func File(g *echo.Group) {
	g.GET("", controllers.IndexFile)
	g.GET("/400.html", controllers.Error400File)
	g.GET("/403.html", controllers.Error403File)
	g.GET("/404.html", controllers.Error404File)
	g.GET("/413.html", controllers.Error413File)
	g.GET("/500.html", controllers.Error500File)
	g.GET("/remove/:file_key", controllers.DeleteFile)
	g.GET("/:file_key", controllers.ReadFile)
	g.POST("/:file_key", controllers.DownloadFile)
	g.POST("", controllers.AddFile)
	g.DELETE("/:file_key", controllers.DeleteFile)
}
