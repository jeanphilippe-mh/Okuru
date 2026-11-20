package controllers

import (
	"net/http"
	"strconv"
	"strings"

	. "github.com/jeanphilippe-mh/Okuru/models"
	. "github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

func Index(context *echo.Context) error {
	return RenderSecretForm(context, http.StatusOK, "")
}

// RenderSecretForm rebuilds the secret form without redisplaying the secret.
func RenderSecretForm(context *echo.Context, status int, message string) error {
	dataContext := NewDataContext()
	dataContext["csrfToken"] = context.Get("csrf")
	if message != "" {
		dataContext["errors"] = message
		context.Response().Header().Set(echo.HeaderCacheControl, "private, no-store")
	}
	return context.Render(status, "set_password.html", dataContext)
}

func SecurityIndex(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.File("public/.well-known/security.txt")
}

func PrivacyIndex(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusOK, "privacy.html", dataContext)
}

func Error400Index(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusBadRequest, "400.html", dataContext)
}

func Error401Index(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusUnauthorized, "401.html", dataContext)
}

func Error403Index(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusForbidden, "403.html", dataContext)
}

func Error404Index(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusNotFound, "404.html", dataContext)
}

func Error413Index(context *echo.Context) error {
	dataContext := NewDataContext()
	dataContext["maxFileSizeText"] = GetMaxFileSizeText()
	// The form's shorter label rounds non-integral GB values down.
	if sizeMB := MaxFileSize / (1024 * 1024); sizeMB >= 1024 && sizeMB%1024 != 0 {
		dataContext["maxFileSizeText"] = strconv.FormatInt(sizeMB, 10) + " MB"
	}
	return context.Render(http.StatusRequestEntityTooLarge, "request_too_large.html", dataContext)
}

func Error500Index(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusInternalServerError, "500.html", dataContext)
}

func Error501Index(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusNotImplemented, "501.html", dataContext)
}

func Error502Index(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusBadGateway, "502.html", dataContext)
}

func Error503Index(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusServiceUnavailable, "503.html", dataContext)
}

func Error504Index(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusGatewayTimeout, "504.html", dataContext)
}

func Error505Index(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusHTTPVersionNotSupported, "505.html", dataContext)
}

func Error506Index(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusVariantAlsoNegotiates, "506.html", dataContext)
}

func Error507Index(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusInsufficientStorage, "507.html", dataContext)
}

func Error508Index(context *echo.Context) error {
	dataContext := NewDataContext()
	delete(dataContext, "errors")
	return context.Render(http.StatusLoopDetected, "508.html", dataContext)
}

func ReadIndex(context *echo.Context) error {
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
		if _, _, parseErr := ParseToken(p.PasswordKey); parseErr == nil {
			auditUnavailable(context, err, "secret.preview_unavailable", "Secret preview unavailable")
		}
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
		deletableURL = sharePublicOrigin(context) + "/remove/" + p.PasswordKey
	}

	dataContext["p"] = p
	dataContext["ttl"] = GetTTLText(p.TTL)
	dataContext["ttlViews"] = GetViewsText(p.Views)
	dataContext["dlViews"] = GetDownloadsText(p.Views)
	dataContext["deletableText"] = deletableText
	dataContext["deletableURL"] = deletableURL

	if err := context.Render(http.StatusOK, "password.html", dataContext); err != nil {
		return err
	}
	AuditEvent(context, "secret.preview", "Secret preview rendered")
	return nil
}

func RevealPassword(context *echo.Context) error {
	dataContext := NewDataContext()
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

	err := RetrievePassword(p)
	if err != nil {
		if _, _, parseErr := ParseToken(p.PasswordKey); parseErr == nil {
			auditUnavailable(context, err, "secret.reveal_unavailable", "Secret retrieval unavailable")
		}
		return context.NoContent(http.StatusNotFound)
	}

	if err := context.String(http.StatusOK, p.Password); err != nil {
		return err
	}
	AuditEvent(context, "secret.reveal", "Secret response written")
	return nil
}

func AddIndex(context *echo.Context) error {
	dataContext := NewDataContext()
	dataContext["csrfToken"] = context.Get("csrf")
	fail := func(status int, message string) error {
		dataContext["errors"] = message
		return RenderFormError(context, status, "set_password.html", "/", dataContext)
	}

	var err error
	p := new(Password)
	p.Password = context.FormValue("password")
	if err := ValidateSecretLength(p.Password); err != nil {
		return fail(http.StatusRequestEntityTooLarge, "Secret exceeds the maximum size")
	}

	p.TTL, err = ParseWebNumber(context.FormValue("ttl"))
	if err != nil {
		AuditAlert(context, "request.invalid_duration", "Invalid duration field")
		return fail(http.StatusBadRequest, "Invalid duration")
	}

	p.Views, err = ParseWebNumber(context.FormValue("ttlViews"))
	if err != nil {
		AuditAlert(context, "request.invalid_attempt_count", "Invalid attempt count field")
		return fail(http.StatusBadRequest, "Invalid attempt count")
	}

	p.Deletable = false
	if err := ValidateWebLimits(p.TTL, p.Views); err != nil {
		return fail(http.StatusBadRequest, displayError(err.Error()))
	}

	if context.FormValue("deletable") == "on" {
		p.Deletable = true
	}

	if err := context.Validate(p); err != nil {
		AuditAlert(context, "secret.invalid_metadata", "Invalid secret metadata")
		return fail(http.StatusOK, "A problem occured during the processus. Please contact the administrator of the website")
	}

	if p.Password == "" {
		return fail(http.StatusOK, "No input was provided. Please fill the following field to generate a link")
	}

	if p.TTL > 30 {
		return fail(http.StatusOK, "TTL is too high")
	}

	p.TTL = GetTtlSeconds(p.TTL)
	if admissionErr := admitSecretCreation(context); admissionErr != nil {
		return fail(admissionErr.Code, admissionErr.Message)
	}

	// Need to use err2 since it's not an error but an http error and it don't return nil otherwise.
	token, err2 := SetPassword(p.Password, p.TTL, p.Views, p.Deletable)
	if err2 != nil {
		AuditError(context, "secret.create_failed", "Secret creation failed")
		if err2.Code == http.StatusServiceUnavailable {
			return fail(http.StatusServiceUnavailable, "Secret storage is temporarily unavailable")
		}
		return fail(http.StatusOK, "A problem occured during the processus. Please contact the administrator of the website")
	}
	AuditEvent(context, "secret.create", "Secret created")

	var (
		deletableText,
		deletableURL string
	)

	baseUrl := sharePublicOrigin(context) + "/"
	if !p.Deletable {
		deletableText = "not deletable"
	} else {
		deletableText = "deletable"
		deletableURL = baseUrl + "remove/" + token
	}
	link := shareLink(context, token, false)
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

func DeleteIndex(context *echo.Context) error {
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
		if _, _, parseErr := ParseToken(p.PasswordKey); parseErr == nil {
			auditUnavailable(context, err, "secret.delete_unavailable", "Secret deletion unavailable")
		}
		status = err.Code
		return context.Render(status, "403.html", dataContext)
	} else {
		AuditEvent(context, "secret.delete", "Secret deleted")
		dataContext["type"] = "Password"
		return context.Render(http.StatusOK, "removed.html", dataContext)
	}
}
