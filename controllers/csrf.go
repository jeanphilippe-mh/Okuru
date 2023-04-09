package controllers

import (
	"net/http"

	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

func getCSRFToken(context echo.Context) error {
	delete(DataContext, "errors")
	csrfToken := context.Get("csrf_token")

	if csrfToken == nil {
		err := errors.New("Failed to retrieve CSRF token")
		log.Error("%+v\n", err)
		return context.Render(http.StatusBadRequest, "403.html", DataContext)
	}

	return context.JSON(http.StatusOK, map[string]string{"csrfToken": csrfToken.(string)})
}
