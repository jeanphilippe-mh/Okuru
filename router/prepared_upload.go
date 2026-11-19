package router

import (
	"context"
	"github.com/jeanphilippe-mh/Okuru/controllers"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
	"io"
	"mime"
	"strings"
	"time"
)

const preparedFilePath = "/api/v2/files"
const sessionPath = "/api/v2/uploads"

func isFileAPIPath(path string) bool {
	return path == directFilePath || path == preparedFilePath || path == sessionPath || strings.HasPrefix(path, sessionPath+"/")
}
func registerPreparedRoutes(e *echo.Echo) {
	e.POST(sessionPath, controllers.PrepareUploadSession)
	e.GET(sessionPath+"/:id", controllers.GetUploadSession)
	e.GET(sessionPath+"/:id/result", controllers.GetUploadSessionResult)
	e.DELETE(sessionPath+"/:id", controllers.AbortUploadSession)
	e.POST(preparedFilePath, controllers.PublishMultipartSession)
}

type uploadCounter struct {
	io.ReadCloser
	id, bearer string
	ctx        context.Context
	n          int64
	last       time.Time
}

func (b *uploadCounter) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	b.n += int64(n)
	if n > 0 && time.Since(b.last) >= time.Second || err == io.EOF {
		if update := utils.SetMultipartProgress(b.ctx, b.id, b.bearer, b.n); update != nil {
			return n, update
		}
		b.last = time.Now()
	}
	return n, err
}

// Authenticate before admission, before any form extraction and before consuming files.
func receivePreparedMultipart(c *echo.Context, next echo.HandlerFunc) error {
	r := c.Request()
	id, bearer := r.Header.Get("Upload-Id"), utils.UploadBearer(r)
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "multipart/form-data" || params["boundary"] == "" {
		closeUnreadHTTP1(c)
		return echo.ErrUnsupportedMediaType
	}
	session, err := utils.AuthorizeUploadSession(r.Context(), id, bearer, false)
	if err != nil {
		closeUnreadHTTP1(c)
		return controllers.UploadSessionErrorResponse(c, err)
	}
	if session.Mode != "multipart" {
		closeUnreadHTTP1(c)
		return c.JSON(409, map[string]string{"code": "wrong_mode", "message": "Multipart session required"})
	}
	if session.State == "ready" {
		closeUnreadHTTP1(c)
		return c.JSON(409, map[string]string{"code": "already_ready", "message": "Share already published"})
	}
	release, err := utils.LockUploadSession(id)
	if err != nil {
		closeUnreadHTTP1(c)
		return controllers.UploadSessionErrorResponse(c, err)
	}
	defer release()
	if err = utils.BeginMultipartAttempt(r.Context(), id, bearer, r.ContentLength); err != nil {
		closeUnreadHTTP1(c)
		return controllers.UploadSessionErrorResponse(c, err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = utils.ResetUploadAttempt(ctx, id, bearer)
	}()
	r.Body = &uploadCounter{ReadCloser: r.Body, ctx: r.Context(), id: id, bearer: bearer}
	c.Set("okuru-prepared-upload", session)
	return next(c)
}
