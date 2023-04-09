package controllers

import (
	"net/http"
	"log"
	"github.com/labstack/echo/v4"
)

func getCSRFToken(c echo.Context) error {
    delete(DataContext, "errors")
    csrfToken := c.Get("csrf_token")

    if csrfToken == nil {
        err := errors.New("Failed to retrieve CSRF token")
        log.Error("%+v\n", err)
        return c.Render(http.StatusBadRequest, "403.html", DataContext)
    }
    return c.JSON(http.StatusOK, map[string]string{"csrfToken": csrfToken.(string)})
}
