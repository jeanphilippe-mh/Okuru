package controllers

import (
	"crypto/rand"
	"crypto/subtle"
	"mime"
	"net/http"
	"os"
	"strings"

	"github.com/jeanphilippe-mh/Okuru/models"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

const secretAPICookie = "__Host-okuru-secret-csrf"

func BootstrapSecretAPI(c *echo.Context) error {
	cookie, err := c.Cookie(secretAPICookie)
	if err != nil || cookie.Value == "" {
		cookie = &http.Cookie{Name: secretAPICookie, Value: rand.Text(), Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
		c.SetCookie(cookie)
	}
	c.Response().Header().Set("X-CSRF-Token", cookie.Value)
	return c.JSON(http.StatusOK, map[string]any{"create_url": "/api/v2/secrets", "max_secret_bytes": utils.MaxSecretBytes})
}

func SecretAPIGuard(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		c.Response().Header().Set("Cache-Control", "private, no-store")
		c.Response().Header().Set("Referrer-Policy", "no-referrer")
		r := c.Request()
		// Reading a secret consumes a view. Reject explicit cross-site browser
		// requests before storage access, including navigations and prefetches.
		site := r.Header.Get("Sec-Fetch-Site")
		if site != "" && site != "same-origin" && site != "none" {
			return echo.ErrForbidden
		}
		if r.Method == http.MethodPost || r.Method == http.MethodDelete {
			cookie, err := c.Cookie(secretAPICookie)
			values := r.Header.Values("X-CSRF-Token")
			if err != nil || len(values) != 1 || values[0] == "" ||
				subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(values[0])) != 1 {
				return echo.ErrForbidden
			}
		}
		return next(c)
	}
}

type secretCreated struct {
	Link       string `json:"link"`
	APILink    string `json:"api_link"`
	TTLSeconds int    `json:"ttl_seconds"`
	Views      int    `json:"views"`
	Deletable  bool   `json:"deletable"`
}

func CreateSecretAPI(c *echo.Context) error {
	req := c.Request()
	media, params, err := mime.ParseMediaType(req.Header.Get("Content-Type"))
	if err != nil || len(req.Header.Values("Content-Type")) != 1 || media != "application/json" ||
		(params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		return echo.ErrUnsupportedMediaType
	}
	input, status := utils.ReadSecretAPIInput(req.Body)
	if status != 0 {
		return echo.NewHTTPError(status, http.StatusText(status))
	}
	if err := admitSecretCreation(c); err != nil {
		return err
	}
	token, storageErr := utils.SetPassword(input.Password, input.TTLSeconds, input.Views, input.Deletable)
	if storageErr != nil {
		utils.AuditError(c, "secret.create_failed", "Secret creation failed")
		return echo.NewHTTPError(storageErr.Code, http.StatusText(storageErr.Code))
	}
	origin, configured := shortLinkPublicOrigin(os.Getenv("OKURU_SHORTLINK_PUBLIC_ORIGIN"))
	result := secretCreated{Link: origin + sharePath(c, token, false, configured), APILink: origin + "/api/v2/secrets/" + token,
		TTLSeconds: input.TTLSeconds, Views: input.Views, Deletable: input.Deletable}
	utils.AuditEvent(c, "secret.create", "Secret created")
	return c.JSON(http.StatusCreated, result)
}

func ReadSecretAPI(c *echo.Context) error {
	p := models.Password{PasswordKey: c.Param("token")}
	if _, _, err := utils.ParseToken(p.PasswordKey); err != nil {
		return echo.ErrNotFound
	}
	if err := utils.RetrievePassword(&p); err != nil {
		auditUnavailable(c, err, "secret.reveal_unavailable", "Secret retrieval unavailable")
		return echo.ErrNotFound
	}
	if err := c.JSON(http.StatusOK, struct {
		Password   string `json:"password"`
		TTLSeconds int    `json:"ttl_seconds"`
		Views      int    `json:"views"`
		Deletable  bool   `json:"deletable"`
	}{p.Password, p.TTL, p.Views, p.Deletable}); err != nil {
		return err
	}
	utils.AuditEvent(c, "secret.reveal", "Secret response written")
	return nil
}

func DeleteSecretAPI(c *echo.Context) error {
	p := models.Password{PasswordKey: c.Param("token")}
	if _, _, err := utils.ParseToken(p.PasswordKey); err != nil {
		return echo.ErrNotFound
	}
	if err := utils.RemovePassword(&p); err != nil {
		auditUnavailable(c, err, "secret.delete_unavailable", "Secret deletion unavailable")
		if err.Code == http.StatusUnauthorized {
			return echo.ErrForbidden
		}
		return echo.NewHTTPError(err.Code, http.StatusText(err.Code))
	}
	utils.AuditEvent(c, "secret.delete", "Secret deleted")
	return c.NoContent(http.StatusNoContent)
}
