package controllers

import (
	"net/http"
	"strconv"
	"strings"

	. "github.com/jeanphilippe-mh/Okuru/models"
	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v4"
	log "github.com/sirupsen/logrus"
)

func Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	csrfToken := context.Get("csrf")
	dataContext["csrfToken"] = csrfToken
	return context.Render(http.StatusOK, "set_password.html", dataContext)
}

func SecurityIndex(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.File("public/.well-known/security.txt")
}

func PrivacyIndex(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusOK, "privacy.html", dataContext)
}

func Error400Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusBadRequest, "400.html", dataContext)
}

func Error401Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusUnauthorized, "401.html", dataContext)
}

func Error403Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusForbidden, "403.html", dataContext)
}

func Error404Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusNotFound, "404.html", dataContext)
}

func Error413Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusRequestEntityTooLarge, "413.html", dataContext)
}

func Error500Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusInternalServerError, "500.html", dataContext)
}

func Error501Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusNotImplemented, "501.html", dataContext)
}

func Error502Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusBadGateway, "502.html", dataContext)
}

func Error503Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusServiceUnavailable, "503.html", dataContext)
}

func Error504Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusGatewayTimeout, "504.html", dataContext)
}

func Error505Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusHTTPVersionNotSupported, "505.html", dataContext)
}

func Error506Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusVariantAlsoNegotiates, "506.html", dataContext)
}

func Error507Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusInsufficientStorage, "507.html", dataContext)
}

func Error508Index(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusLoopDetected, "508.html", dataContext)
}

func ReadIndex(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	// Retrieve the CSRF token
	csrfToken := context.Get("csrf")
	dataContext["csrfToken"] = csrfToken

	p := new(Password)
	p.PasswordKey = context.Param("password_key")

	if p.PasswordKey == "" {
		return context.NoContent(http.StatusNotFound)
	}
	if strings.Contains(p.PasswordKey, "favicon.ico") {
		return nil
	}
	if strings.Contains(p.PasswordKey, "robots.txt") {
		return nil
	}
	if strings.Contains(p.PasswordKey, "sitemap.xml") {
		return nil
	}

	err := GetPassword(p)
	if err != nil {
		log.Error("Error while retrieving password : %s\n")
		return context.Render(http.StatusForbidden, "403.html", dataContext)
	}

	var (
		deletableText,
		deletableURL string
	)

	if !p.Deletable {
		deletableText = "not deletable"
	} else {
		deletableText = "deletable"
		deletableURL = GetBaseUrl(context) + "/remove/" + p.PasswordKey
	}

	dataContext["p"] = p
	dataContext["ttl"] = GetTTLText(p.TTL)
	dataContext["ttlViews"] = GetViewsText(p.Views)
	dataContext["dlViews"] = GetDownloadsText(p.Views)
	dataContext["deletableText"] = deletableText
	dataContext["deletableURL"] = deletableURL

	return context.Render(http.StatusOK, "password.html", dataContext)
}

func RevealPassword(context echo.Context) error {
	dataContext := NewDataContext()
	// Retrieve the CSRF token
	csrfToken := context.Get("csrf")
	dataContext["csrfToken"] = csrfToken

	println("\n/ Password has been revealed by a viewver /\n")
	p := new(Password)
	p.PasswordKey = context.Param("password_key")
	if p.PasswordKey == "" {
		return context.NoContent(http.StatusNotFound)
	}
	if strings.Contains(p.PasswordKey, "favicon.ico") {
		return nil
	}
	if strings.Contains(p.PasswordKey, "robots.txt") {
		return nil
	}
	if strings.Contains(p.PasswordKey, "sitemap.xml") {
		return nil
	}

	err := RetrievePassword(p)
	if err != nil {
		log.Error("%+v\n", err)
		return context.NoContent(http.StatusNotFound)
	}

	return context.String(200, p.Password)
}

func AddIndex(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	// Retrieve the CSRF token
	csrfToken := context.Get("csrf")
	dataContext["csrfToken"] = csrfToken

	var err error
	p := new(Password)
	p.Password = context.FormValue("password")

	p.TTL, err = strconv.Atoi(context.FormValue("ttl"))
	if err != nil {
		log.Error("%+v\n", err)
		dataContext["errors"] = err.Error()
		return context.Render(http.StatusBadRequest, "set_password.html", dataContext)
	}

	p.Views, err = strconv.Atoi(context.FormValue("ttlViews"))
	if err != nil {
		log.Error("%+v\n", err)
		dataContext["errors"] = err.Error()
		return context.Render(http.StatusBadRequest, "set_password.html", dataContext)
	}

	p.Deletable = false
	if err := ValidateWebLimits(p.TTL, p.Views); err != nil {
		dataContext["errors"] = err.Error()
		return context.Render(http.StatusBadRequest, "set_password.html", dataContext)
	}

	if context.FormValue("deletable") == "on" {
		p.Deletable = true
	}

	if err := context.Validate(p); err != nil {
		log.Error("%+v\n", err)
		dataContext["errors"] = "A problem occured during the processus. Please contact the administrator of the website"
		return context.Render(http.StatusOK, "set_password.html", dataContext)
	}

	if p.Password == "" {
		dataContext["errors"] = "No input was provided. Please fill the following field to generate a link"
		return context.Render(http.StatusOK, "set_password.html", dataContext)
	}

	if p.TTL > 30 {
		dataContext["errors"] = "TTL is too high"
		return context.Render(http.StatusOK, "set_password.html", dataContext)
	}

	p.TTL = GetTtlSeconds(p.TTL)

	// Need to use err2 since it's not an error but an http error and it don't return nil otherwise.
	token, err2 := SetPassword(p.Password, p.TTL, p.Views, p.Deletable)
	if err2 != nil {
		dataContext["errors"] = "A problem occured during the processus. Please contact the administrator of the website"
		return context.Render(http.StatusOK, "set_password.html", dataContext)
	}

	var (
		deletableText,
		deletableURL string
	)

	baseUrl := GetBaseUrl(context) + "/"
	if !p.Deletable {
		deletableText = "not deletable"
	} else {
		deletableText = "deletable"
		deletableURL = baseUrl + "remove/" + token
	}
	link := baseUrl + token
	p.PasswordKey = token
	p.Link = link
	p.Password = ""

	dataContext["p"] = p
	dataContext["ttl"] = GetTTLText(p.TTL)
	dataContext["ttlViews"] = GetViewsText(p.Views)
	dataContext["dlViews"] = GetDownloadsText(p.Views)
	dataContext["deletableText"] = deletableText
	dataContext["deletableURL"] = deletableURL

	return context.Render(http.StatusOK, "confirm.html", dataContext)
}

func DeleteIndex(context echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	// Retrieve the CSRF token
	csrfToken := context.Get("csrf")
	dataContext["csrfToken"] = csrfToken

	p := new(Password)
	p.PasswordKey = context.Param("password_key")
	if p.PasswordKey == "" || strings.Contains(p.PasswordKey, "*") {
		return context.NoContent(http.StatusNotFound)
	}

	err := RemovePassword(p)
	var status int
	if err != nil {
		status = err.Code
		return context.Render(status, "403.html", dataContext)
	} else {
		dataContext["type"] = "Password"
		return context.Render(http.StatusOK, "removed.html", dataContext)
	}
}
