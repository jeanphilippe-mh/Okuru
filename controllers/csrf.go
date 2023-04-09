package controllers

import (
	"github.com/labstack/echo/v4"
)

func GetCSRFToken(c echo.Context) error {
	token := c.Get("csrf").(string)
	return c.JSON(200, map[string]string{
		"csrfToken": token,
	})
}
