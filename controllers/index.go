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
	delete(DataContext, "errors")
	return context.Render(http.StatusOK, "set_password.html", DataContext)
}

func PrivacyIndex(context echo.Context) error {
	delete(DataContext, "errors")
	return context.Render(http.StatusOK, "privacy.html", DataContext)
}

func ReadIndex(context echo.Context) error {
	delete(DataContext, "errors")
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
		log.Error("Error while retrieving password : %s\n", err)
		return context.Render(http.StatusNotFound, "404.html", DataContext)
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

	DataContext["p"] = p
	DataContext["ttl"] = GetTTLText(p.TTL)
	DataContext["p.Views"] = GetViewsText(p.Views)
	DataContext["deletableText"] = deletableText
	DataContext["deletableURL"] = deletableURL

	return context.Render(http.StatusOK, "password.html", DataContext)
}

func RevealPassword(context echo.Context) error {
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
	delete(DataContext, "errors")
	var err error
	p := new(Password)
	p.Password = context.FormValue("password")

	p.TTL, err = strconv.Atoi(context.FormValue("ttl"))
	if err != nil {
		log.Error("%+v\n", err)
		DataContext["errors"] = err.Error()
		return context.Render(http.StatusOK, "set_password.html", DataContext)
	}

	p.Views, err = strconv.Atoi(context.FormValue("ttlViews"))
	if err != nil {
		log.Error("%+v\n", err)
		DataContext["errors"] = err.Error()
		return context.Render(http.StatusOK, "set_password.html", DataContext)
	}

	p.Deletable = false
	if context.FormValue("deletable") == "on" {
		p.Deletable = true
	}

	if err := context.Validate(p); err != nil {
		log.Error("%+v\n", err)
		DataContext["errors"] = "A problem occured during the processus. Please contact the administrator of the website"
		return context.Render(http.StatusOK, "set_password.html", DataContext)
	}

	if p.Password == "" {
		DataContext["errors"] = "No input was provided. Please fill the following field to generate a link"
		return context.Render(http.StatusOK, "set_password.html", DataContext)
	}

	if p.TTL > 30 {
		DataContext["errors"] = "TTL is too high"
		return context.Render(http.StatusOK, "set_password.html", DataContext)
	}

	p.TTL = GetTtlSeconds(p.TTL)

	// Need to use err2 since it's not an error but an http error and it don't return nil otherwise.
	token, err2 := SetPassword(p.Password, p.TTL, p.Views, p.Deletable)
	if err2 != nil {
		DataContext["errors"] = "A problem occured during the processus. Please contact the administrator of the website"
		return context.Render(http.StatusOK, "set_password.html", DataContext)
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

	DataContext["p"] = p
	DataContext["ttl"] = GetTTLText(p.TTL)
	DataContext["p.Views"] = GetViewsText(p.Views)
	DataContext["deletableText"] = deletableText
	DataContext["deletableURL"] = deletableURL

	return context.Render(http.StatusOK, "confirm.html", DataContext)
}

func DeleteIndex(context echo.Context) error {
	delete(DataContext, "errors")
	p := new(Password)
	p.PasswordKey = context.Param("password_key")
	if p.PasswordKey == "" || strings.Contains(p.PasswordKey, "*") {
		return context.NoContent(http.StatusNotFound)
	}

	err := RemovePassword(p)
	var status int
	if err != nil {
		status = err.Code
		return context.Render(status, "404.html", DataContext)
	} else {
		DataContext["type"] = "Password"
		return context.Render(http.StatusOK, "removed.html", DataContext)
	}
}
