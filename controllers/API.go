package controllers

import (
	"github.com/jeanphilippe-mh/Okuru/models"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	"net/http"
	"strings"
)

/**
 * Print help for API usage in a readable way for bash/curl call
 */
func HelpPassword(context echo.Context) error {
	help := `Generate a password share link with the following parameters:
password : (required), the password
ttl: (optional) number seconds, min: 300, max: 604800, default: 3600 (one hour)
views: (optional) number between 1 and 100
deletable: (optional) boolean (false, true), default: false
For example with the following command:
curl -X POST -H "Content-Type:application/json" -d '{"password":"password-here","ttl":seconds, "views":views, "deletable": true}' ` + GetBaseUrl(context) + "/api/v1"
	return context.String(http.StatusOK, help)
}

/**
 * From a given token, return the initial password, we decrypt the password fetched from Redis.
 */
func ReadPassword(context echo.Context) error {
	p := new(Password)
	p.PasswordKey = context.Param("password_key")
	if p.PasswordKey == "" {
		return context.NoContent(http.StatusNotFound)
	}

	err := GetPassword(p)
	if err != nil {
		return context.NoContent(http.StatusNotFound)
	}

	// Empty var so json response don't have them
	p.Token = []byte("")
	p.PasswordKey = ""
	return context.JSON(http.StatusOK, p)
}

/**
 * From a give password, return link
 */
func CreatePassword(context echo.Context) (err error) {
	p := new(Password)
	if err := context.Bind(p); err != nil {
		return context.NoContent(http.StatusBadRequest)
	}
	if err := context.Validate(p); err != nil {
		return context.NoContent(http.StatusBadRequest)
	}

	if p.Views == 0 {
		p.Views = 1
	}
	if p.Views > 100 {
		return context.JSON(http.StatusBadRequest, "Views too high (max 100)")
	}
	if p.TTL == 0 {
		p.TTL = 3600
	}
	if p.TTL > 604800 {
		return context.JSON(http.StatusBadRequest, "TTL too high (max 604800 seconds)")
	}

	token, err2 := SetPassword(p.Password, p.TTL, p.Views, p.Deletable)
	if err2 != nil {
		return context.JSON(http.StatusInternalServerError, "A problem occured during the processus. Please contact the administrator of the website")
	}

	baseUrl := GetBaseUrl(context) + "/"
	p.PasswordKey = token
	p.Link = baseUrl + token
	p.LinkApi = baseUrl + "api/v1/" + token

	// Empty var so json response don't have them
	p.Token = []byte("")
	p.Password = ""
	p.PasswordKey = ""

	return context.JSON(http.StatusCreated, p)
}

/**
 * From a given token, remove password from Redis.
 */
func DeletePassword(context echo.Context) error {
	p := new(Password)
	p.PasswordKey = context.Param("password_key")
	if p.PasswordKey == "" || strings.Contains(p.PasswordKey, "*") {
		return context.NoContent(http.StatusNotFound)
	}

	err := RemovePassword(p)
	var status int
	if err != nil {
		status = err.Code
	} else {
		status = http.StatusOK
	}
	return context.NoContent(status)
}
