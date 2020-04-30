package routes

import (
	"github.com/jeanphilippe-mh/Okuru/controllers"
	"github.com/labstack/echo"
)

func File(g *echo.Group) {
	g.GET("", controllers.IndexFile)
	g.GET("/remove/:file_key", controllers.DeleteFile)
	g.GET("/:file_key", controllers.ReadFile)
	g.POST("/:file_key", controllers.DownloadFile)
	g.POST("", controllers.AddFile)
	g.DELETE("/:file_key", controllers.DeleteFile)
}
