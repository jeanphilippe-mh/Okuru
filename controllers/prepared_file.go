package controllers

import (
	"context"
	"encoding/json"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// The caller holds the session lock until publication or compensation is done.
func publishPreparedFile(c *echo.Context, s *utils.UploadSession, bearer string, sources []utils.UploadArchiveSource) error {
	ctx := c.Request().Context()
	m := s.Metadata
	if m == nil || len(sources) != len(m.Files) {
		return uploadSessionHTTPResponse(c, 409, "incomplete")
	}
	for i, src := range sources {
		if src.Filename != m.Files[i].Name || src.Size != m.Files[i].Size {
			return uploadSessionHTTPResponse(c, 409, "incomplete")
		}
	}
	if err := utils.BeginUploadPublication(ctx, s.ID, bearer); err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	retained := false
	defer func() {
		if !retained {
			cleanup, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = utils.RevertUploadPublication(cleanup, s.ID, bearer)
		}
	}()
	if err := admitFileCreation(c); err != nil {
		return err
	}
	stage, err := utils.CreateLockedStagingDir(utils.FILEFOLDER, ".okuru-upload-")
	if err != nil {
		return echo.NewHTTPError(http.StatusInsufficientStorage, "Insufficient storage")
	}
	defer stage.Close()
	secret, format := m.Password, utils.ArchiveFormatAgeUserPassword
	var release func()
	if secret == "" {
		secret, err = utils.GenerateArchiveIdentity()
		if err != nil {
			return echo.ErrInternalServerError
		}
		format = utils.ArchiveFormatAgeX25519
	} else {
		ctx, release, err = utils.ReserveArchiveKDF(ctx)
		if err != nil {
			return echo.ErrServiceUnavailable
		}
		defer release()
		if err = admitArchiveKDF(c, "", false); err != nil {
			return err
		}
	}
	path := filepath.Join(stage.Path, "archive.tmp")
	if err = writeUploadArchive(ctx, path, secret, sources, format, release); err != nil {
		return echo.ErrInternalServerError
	}
	p, fileToken, passwordToken, err := utils.PrepareUploadRecords(s.ID, m, secret, format)
	if err != nil {
		return echo.ErrInternalServerError
	}
	view := fileConfirmation{FilePath: "/file/" + fileToken, TTL: m.TTLSeconds, Views: m.Views}
	origin, _ := shortLinkPublicOrigin(os.Getenv("OKURU_SHORTLINK_PUBLIC_ORIGIN"))
	result := map[string]string{"link": origin + view.FilePath}
	if m.Deletable {
		view.DeletePath = "/file/remove/" + fileToken
		result["delete_link"] = origin + view.DeletePath
	}
	if passwordToken != "" {
		view.PasswordPath = "/" + passwordToken
		result["password_link"] = origin + view.PasswordPath
	}
	receipt, digest, err := encodeFileReceipt(p.FileID, view, time.Now(), true)
	if err != nil {
		return echo.ErrInternalServerError
	}
	result["confirmation_receipt"] = receipt
	p.ConfirmationDigest = digest
	raw, err := json.Marshal(result)
	if err != nil {
		return echo.ErrInternalServerError
	}
	p.Result, err = utils.SealUploadResult(s.ID, bearer, raw)
	if err != nil {
		return echo.ErrInternalServerError
	}
	retained, err = p.Save(ctx, bearer, path)
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	raw, err = utils.ReadUploadResult(ctx, s.ID, bearer)
	if err != nil {
		return UploadSessionErrorResponse(c, err)
	}
	utils.AuditEvent(c, "file.upload", "Prepared file share published")
	return c.JSON(http.StatusCreated, json.RawMessage(raw))
}

func PublishMultipartSession(c *echo.Context) error {
	r := c.Request()
	s, _ := c.Get("okuru-prepared-upload").(*utils.UploadSession)
	f := utils.GetSecureMultipart(r)
	if s == nil || f == nil {
		return echo.ErrBadRequest
	}
	names, err := validateUploadFiles(f.Files)
	if err != nil {
		return echo.ErrBadRequest
	}
	return publishPreparedFile(c, s, utils.UploadBearer(r), multipartArchiveSources(f.Files, names))
}
