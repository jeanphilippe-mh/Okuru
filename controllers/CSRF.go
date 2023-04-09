package controllers

import (
	"errors"
	"net/http"

	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

func GetCSRFToken(context echo.Context) error {
	delete(DataContext, "errors")
	csrfToken := context.Get("csrf_token")

	if csrfToken == nil {
		err := errors.New("Failed to retrieve CSRF token")
		log.Errorf("%+v\n", err)
		return context.Render(http.StatusBadRequest, "403.html", DataContext)
	}

	log.Infof("CSRF token retrieved successfully: %v\n", csrfToken)

	return context.JSON(http.StatusOK, map[string]string{"csrfToken": csrfToken.(string)})
}
