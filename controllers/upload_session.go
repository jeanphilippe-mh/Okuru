package controllers

import (
	"encoding/json"
	"mime"
	"net/http"
	"strconv"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

func privateUploadResponse(c *echo.Context) {
	c.Response().Header().Set("Cache-Control", "private, no-store")
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
}

func UploadSessionErrorResponse(c *echo.Context, err error) error {
	status, code := utils.UploadSessionHTTPError(err)
	return uploadSessionHTTPResponse(c, status, code)
}

func uploadSessionHTTPResponse(c *echo.Context, status int, code string) error {
	privateUploadResponse(c)
	if c.Request().Method == http.MethodHead {
		return c.NoContent(status)
	}
	return c.JSON(status, map[string]string{"code": code, "message": http.StatusText(status)})
}

func PrepareUploadSession(c *echo.Context) error {
	privateUploadResponse(c)
	r := c.Request()
	typ, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || typ != "application/json" || len(r.Header.Values("Content-Type")) != 1 || (params["charset"] != "" && params["charset"] != "utf-8" && params["charset"] != "UTF-8") {
		return uploadSessionHTTPResponse(c, 415, "unsupported_media_type")
	}
	if len(r.Header.Values("Idempotency-Key")) != 1 {
		return uploadSessionHTTPResponse(c, 400, "invalid_id")
	}
	bearer := utils.UploadBearer(r)
	if bearer == "" {
		return uploadSessionHTTPResponse(c, 404, "not_found")
	}
	manifest, err := utils.ParseUploadManifest(r.Body, utils.MaxFileSize)
	if err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	s, created, err := utils.PrepareFileUploadSession(r.Context(), r, r.Header.Get("Idempotency-Key"), bearer, manifest)
	if err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	statusURL := "/api/v2/uploads/" + s.ID
	type item struct {
		Index int    `json:"index"`
		Name  string `json:"name"`
		Size  int64  `json:"size"`
		URL   string `json:"upload_url"`
	}
	files := make([]item, 0, len(s.Metadata.Files))
	for n, f := range s.Metadata.Files {
		url := "/api/v2/files"
		if s.Mode == "blocks" {
			url = statusURL + "/files/" + strconv.Itoa(n)
		}
		files = append(files, item{n, f.Name, f.Size, url})
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
		c.Response().Header().Set("Location", statusURL)
	}
	return c.JSON(status, map[string]any{"id": s.ID, "mode": s.Mode, "expires_at": s.ExpiresAt, "status_url": statusURL, "status_token": s.StatusToken, "result_url": statusURL + "/result", "files": files})
}

func GetUploadSession(c *echo.Context) error {
	privateUploadResponse(c)
	r := c.Request()
	s, err := utils.AuthorizeUploadSession(r.Context(), c.Param("id"), utils.UploadBearer(r), true)
	if err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	var total any
	if s.Total >= 0 {
		total = s.Total
	}
	measure := "http_body"
	if s.Mode == "blocks" {
		measure = "file_bytes_confirmed"
	}
	return c.JSON(http.StatusOK, map[string]any{"state": s.State, "measure": measure, "bytes": s.Bytes, "total": total, "expires_at": s.ExpiresAt})
}

func GetUploadSessionResult(c *echo.Context) error {
	privateUploadResponse(c)
	r := c.Request()
	result, err := utils.ReadUploadResult(r.Context(), c.Param("id"), utils.UploadBearer(r))
	if err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	return c.JSON(http.StatusOK, json.RawMessage(result))
}

func AbortUploadSession(c *echo.Context) error {
	privateUploadResponse(c)
	r := c.Request()
	id := c.Param("id")
	bearer := utils.UploadBearer(r)
	_, err := utils.AuthorizeUploadSession(r.Context(), id, bearer, false)
	if err != nil {
		if _, code := utils.UploadSessionHTTPError(err); code != "aborted" {
			return UploadSessionErrorResponse(c, err)
		}
	}
	release, err := utils.LockUploadSession(id)
	if err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	defer release()
	if err = utils.AbortFileUploadSession(r.Context(), id, bearer); err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	if err = utils.CleanupUploadSessionParts(id); err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	return c.NoContent(http.StatusNoContent)
}
