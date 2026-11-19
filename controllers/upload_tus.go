package controllers

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

const TusVersion = "1.0.0"

func UploadTusOptions(c *echo.Context) error {
	privateUploadResponse(c)
	h := c.Response().Header()
	h.Set("Tus-Version", TusVersion)
	h.Set("Tus-Max-Size", strconv.FormatInt(utils.MaxFileSize, 10))
	h.Set("Allow", "OPTIONS, HEAD, PATCH")
	return c.NoContent(http.StatusNoContent)
}

func tusFile(c *echo.Context) (*utils.UploadSession, int, string, bool, error) {
	privateUploadResponse(c)
	r := c.Request()
	bearer := utils.UploadBearer(r)
	s, err := utils.AuthorizeUploadSession(r.Context(), c.Param("id"), bearer, false)
	if err != nil {
		return nil, 0, "", false, UploadSessionErrorResponse(c, err)
	}
	if s.Mode != "blocks" {
		return nil, 0, "", false, uploadSessionHTTPResponse(c, http.StatusConflict, "wrong_mode")
	}
	raw := c.Param("index")
	index, err := strconv.Atoi(raw)
	if err != nil || index < 0 || strconv.Itoa(index) != raw || index >= len(s.Metadata.Files) {
		return nil, 0, "", false, uploadSessionHTTPResponse(c, http.StatusNotFound, "not_found")
	}
	return s, index, bearer, true, nil
}

func UploadTusHead(c *echo.Context) error {
	s, index, bearer, ok, err := tusFile(c)
	if !ok {
		return err
	}
	offset, err := utils.ConfirmedUploadOffset(c.Request().Context(), s.ID, bearer, index)
	if err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	h := c.Response().Header()
	h.Set("Upload-Offset", strconv.FormatInt(offset, 10))
	h.Set("Upload-Length", strconv.FormatInt(s.Metadata.Files[index].Size, 10))
	return c.NoContent(http.StatusOK)
}

func UploadTusPatch(c *echo.Context) error {
	s, index, bearer, ok, err := tusFile(c)
	if !ok {
		return err
	}
	r := c.Request()
	if len(r.Header.Values("Content-Type")) != 1 || r.Header.Get("Content-Type") != "application/offset+octet-stream" {
		return uploadSessionHTTPResponse(c, http.StatusUnsupportedMediaType, "unsupported_media_type")
	}
	raw := r.Header.Get("Upload-Offset")
	offset, err := strconv.ParseInt(raw, 10, 64)
	if len(r.Header.Values("Upload-Offset")) != 1 || err != nil || offset < 0 || strconv.FormatInt(offset, 10) != raw {
		return uploadSessionHTTPResponse(c, http.StatusBadRequest, "invalid_offset")
	}
	unlock, err := utils.LockUploadSession(s.ID)
	if err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	defer unlock()
	position, err := utils.AppendUploadPart(r.Context(), s, bearer, index, offset, r.ContentLength, utils.UploadPatchLimit(), r.Body)
	if err != nil {
		if errors.Is(err, utils.ErrStorageCapacity) {
			return uploadSessionHTTPResponse(c, http.StatusInsufficientStorage, "insufficient_storage")
		}
		if _, code := utils.UploadSessionHTTPError(err); code == "offset_conflict" {
			c.Response().Header().Set("Upload-Offset", strconv.FormatInt(position, 10))
		}
		return UploadSessionErrorResponse(c, err)
	}
	c.Response().Header().Set("Upload-Offset", strconv.FormatInt(position, 10))
	return c.NoContent(http.StatusNoContent)
}
