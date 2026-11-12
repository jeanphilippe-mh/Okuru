package controllers

import (
	"github.com/google/uuid"
	. "github.com/jeanphilippe-mh/Okuru/models"
	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	"net/http"
	"strings"
)

/**
 * Print help for API usage in a readable way for bash/curl call.
 */
func HelpPassword(context echo.Context) error {
	if token, ok := context.Get("csrf").(string); ok {
		context.Response().Header().Set("X-CSRF-Token", token)
	}
	help := `Generate a password share link:
password: required string
ttl: seconds, min 300, max 604800; omitted/zero defaults to 3600
views: min 1, max 100; omitted/zero defaults to 1
deletable: boolean, default false

First GET this endpoint. Retain the response cookie and X-CSRF-Token header.
Send both back with POST or DELETE. For JSON use Content-Type: application/json.
Example POST body: {"password":"password-here","ttl":3600,"views":1,"deletable":true}

GET /api/v1/<token> reveals the password and consumes one attempt.
DELETE /api/v1/<token> deletes a deletable secret after key and CSRF validation.
See docs/api.md for complete examples.
Endpoint: ` + GetBaseUrl(context) + "/api/v1"

	return context.String(http.StatusOK, help)
}

/**
 * From a given token, return the initial password, we decrypt the password fetched from Redis.
 */
func ReadPassword(context echo.Context) error {
	p := new(Password)
	p.PasswordKey = context.Param("password_key")
	if p.PasswordKey == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	// Secret retrieval cannot select file metadata through its identifier.
	id, key, parseErr := ParseToken(p.PasswordKey)
	canonical, uuidErr := uuid.Parse(id)
	if parseErr != nil || uuidErr != nil || canonical.String() != id || key == "" {
		return echo.NewHTTPError(http.StatusNotFound)
	}
	err := RetrievePassword(p)
	if err != nil {
		return echo.NewHTTPError(http.StatusNotFound)
	}

	// Empty var so json response don't have them.
	p.Token = []byte("")
	p.PasswordKey = ""
	return context.JSON(http.StatusOK, p)
}

/**
 * From a give password, return link.
 */
func CreatePassword(context echo.Context) (err error) {
	// Bind only creation fields; internal storage fields are never client input.
	input := new(createPasswordRequest)
	if err := context.Bind(input); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest)
	}
	if input.Views == 0 {
		input.Views = 1
	}
	if input.TTL == 0 {
		input.TTL = 3600
	}
	if input.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest)
	}
	if err := ValidateSecretLength(input.Password); err != nil {
		return echo.NewHTTPError(http.StatusRequestEntityTooLarge, "secret exceeds the maximum size")
	}
	if err := ValidateAPILimits(input.TTL, input.Views); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest)
	}
	p := &Password{Password: input.Password, TTL: input.TTL, Views: input.Views, Deletable: input.Deletable}

	token, err2 := SetPassword(p.Password, p.TTL, p.Views, p.Deletable)
	if err2 != nil {
		return echo.NewHTTPError(http.StatusInternalServerError)
	}

	baseUrl := GetBaseUrl(context) + "/"
	p.PasswordKey = token
	p.Link = baseUrl + token
	p.LinkApi = baseUrl + "api/v1/" + token

	// Empty var so json response don't have them.
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
		return echo.NewHTTPError(http.StatusNotFound)
	}

	err := RemovePassword(p)
	var status int
	if err != nil {
		status = err.Code
	} else {
		status = http.StatusOK
	}
	if status >= 400 {
		return echo.NewHTTPError(status)
	}
	return context.NoContent(status)
}

// The form tags deliberately omit JSON's ",omitempty" option: Echo treats
// form tag values as literal field names.
type createPasswordRequest struct {
	Password  string `json:"password" form:"password"`
	TTL       int    `json:"ttl" form:"ttl"`
	Views     int    `json:"views" form:"views"`
	Deletable bool   `json:"deletable" form:"deletable"`
}
