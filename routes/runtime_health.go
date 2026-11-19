package routes

import (
	"net/http"

	"github.com/labstack/echo/v5"
)

// RuntimeHealth reserves two small local responses before share routing,
// CSRF cookies, static fallbacks and the application's shared request slots.
// The watchdog can therefore check Echo while Redis or upload capacity is down.
func RuntimeHealth(e *echo.Echo, health interface{ Ready() bool }) {
	e.Pre(func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			r := c.Request()
			path := r.URL.Path
			if path != "/ping" && path != "/ready" {
				return next(c)
			}
			h := c.Response().Header()
			h.Set(echo.HeaderCacheControl, "no-store")
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				h.Set(echo.HeaderAllow, "GET, HEAD")
				return c.NoContent(http.StatusMethodNotAllowed)
			}
			status, code := "alive", http.StatusOK
			if path == "/ready" {
				status = "ready"
				if !health.Ready() {
					status, code = "unavailable", http.StatusServiceUnavailable
				}
			}
			if r.Method == http.MethodHead {
				h.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
				return c.NoContent(code)
			}
			return c.JSON(code, struct {
				Status string `json:"status"`
			}{status})
		}
	})
}
