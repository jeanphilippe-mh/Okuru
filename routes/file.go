package routes

import (
	"github.com/jeanphilippe-mh/Okuru/controllers"
	"github.com/labstack/echo/v4"
)

func File(g *echo.Group) {
	g.GET("", controllers.IndexFile)
	g.GET("/400.html", controllers.Error400Index)
	g.GET("/401.html", controllers.Error401Index)
	g.GET("/403.html", controllers.Error403Index)
	g.GET("/404.html", controllers.Error404Index)
	g.GET("/413.html", controllers.Error413Index)
	g.GET("/500.html", controllers.Error500Index)
	g.GET("/501.html", controllers.Error501Index)
	g.GET("/502.html", controllers.Error502Index)
	g.GET("/503.html", controllers.Error503Index)
	g.GET("/504.html", controllers.Error504Index)
	g.GET("/505.html", controllers.Error505Index)
	g.GET("/506.html", controllers.Error506Index)
	g.GET("/507.html", controllers.Error507Index)
	g.GET("/508.html", controllers.Error508Index)
	g.GET("/509.html", controllers.Error509Index)
	g.GET("/remove/:file_key", controllers.DeleteFile)
	g.GET("/:file_key", controllers.ReadFile)
	g.POST("/:file_key", controllers.DownloadFile)
	g.POST("", controllers.AddFile)
	g.DELETE("/:file_key", controllers.DeleteFile)
}
