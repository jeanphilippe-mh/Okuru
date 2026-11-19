package controllers

import (
	"encoding/json"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	"net/http"
)

func CompleteUploadSession(c *echo.Context) error {
	privateUploadResponse(c)
	r := c.Request()
	ctx := r.Context()
	id, bearer := c.Param("id"), utils.UploadBearer(r)
	s, err := utils.AuthorizeUploadSession(ctx, id, bearer, false)
	if err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	if s.Mode != "blocks" {
		return uploadSessionHTTPResponse(c, 409, "wrong_mode")
	}
	if s.State == "ready" {
		result, err := utils.ReadUploadResult(ctx, id, bearer)
		if err != nil {
			return UploadSessionErrorResponse(c, err)
		}
		return c.JSON(http.StatusOK, json.RawMessage(result))
	}
	unlock, err := utils.LockUploadSession(id)
	if err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	defer unlock()
	s, err = utils.AuthorizeUploadSession(ctx, id, bearer, false)
	if err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	if s.State == "ready" {
		return GetUploadSessionResult(c)
	}
	if s.Bytes != s.Total {
		return uploadSessionHTTPResponse(c, 409, "incomplete")
	}
	files, err := utils.UploadPartSources(ctx, s, bearer)
	if err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	err = publishPreparedFile(c, s, bearer, files)
	if result, e := echo.UnwrapResponse(c.Response()); e == nil && result.Status == http.StatusCreated {
		_ = utils.ReleaseUploadParts(id)
	}
	return err
}
