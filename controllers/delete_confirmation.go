package controllers

import (
	"github.com/jeanphilippe-mh/Okuru/models"
	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	"net/http"
)

// Existing deletion URLs remain usable, but GET is now read-only. Native HTML
// forms perform the deletion through POST and the existing CSRF middleware.
func ConfirmDeleteIndex(c echo.Context) error {
	p := &models.Password{PasswordKey: c.Param("password_key")}
	if err := GetPassword(p); err != nil {
		return c.Render(http.StatusNotFound, "404.html", NewDataContext())
	}
	if !p.Deletable {
		return c.Render(http.StatusUnauthorized, "401.html", NewDataContext())
	}
	return deletionConfirmation(c)
}
func ConfirmDeleteFile(c echo.Context) error {
	f := &models.File{FileKey: c.Param("file_key")}
	if err := GetFileForDeletion(f); err != nil {
		return c.Render(http.StatusNotFound, "404.html", NewDataContext())
	}
	if !f.Deletable {
		return c.Render(http.StatusUnauthorized, "401.html", NewDataContext())
	}
	return deletionConfirmation(c)
}
func deletionConfirmation(c echo.Context) error {
	c.Response().Header().Set("Cache-Control", "no-store")
	data := NewDataContext()
	data["csrfToken"] = c.Get("csrf")
	data["deleteAction"] = c.Request().URL.EscapedPath()
	return c.Render(http.StatusOK, "confirm_delete.html", data)
}
