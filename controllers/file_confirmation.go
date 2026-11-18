package controllers

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/google/uuid"
	"github.com/jeanphilippe-mh/Okuru/models"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

// Only paths created by the upload handler enter the confirmation. Keep the
// original alias on reload, including when short links are enabled.
type fileConfirmation struct {
	FilePath     string `json:"file"`
	PasswordPath string `json:"passwordLink,omitempty"`
	DeletePath   string `json:"delete,omitempty"`
	TTL          int    `json:"ttl"`
	Views        int    `json:"views"`
}

func newFileConfirmation(c *echo.Context, fileToken, passwordToken string, file *models.File) fileConfirmation {
	origin := sharePublicOrigin(c)
	view := fileConfirmation{
		FilePath: strings.TrimPrefix(shareLink(c, fileToken, true), origin),
		TTL:      file.TTL, Views: file.Views,
	}
	if passwordToken != "" {
		view.PasswordPath = strings.TrimPrefix(shareLink(c, passwordToken, false), origin)
	}
	if file.Deletable {
		view.DeletePath = "/file/remove/" + fileToken
	}
	return view
}

func (view fileConfirmation) render(c *echo.Context) error {
	data := utils.NewDataContext()
	delete(data, "errors")
	origin := sharePublicOrigin(c)
	data["csrfToken"] = c.Get("csrf")
	data["f"] = &models.File{Link: origin + view.FilePath, Deletable: view.DeletePath != "", TTL: view.TTL, Views: view.Views}
	data["ttl"] = utils.GetTTLText(view.TTL)
	data["ttlViews"] = utils.GetViewsText(view.Views)
	data["dlViews"] = utils.GetDownloadsText(view.Views)
	data["deletableText"], data["deletableURL"] = "not deletable", ""
	if view.DeletePath != "" {
		data["deletableText"], data["deletableURL"] = "deletable", origin+view.DeletePath
	}
	data["passwordLink"] = ""
	if view.PasswordPath != "" {
		data["passwordLink"] = origin + view.PasswordPath
	}
	c.Response().Header().Set("Cache-Control", "private, no-store")
	return c.Render(http.StatusOK, "confirm_file.html", data)
}

const fileReceiptLifetime = 5 * time.Minute
const maxFileReceiptBytes = 8192

var errFileReceiptUnavailable = errors.New("upload confirmation unavailable")

// A receipt is a temporary bearer credential. Redis only retains its digest.
// Check the original hash and attach the digest atomically, preserving its expiry.
var attachFileReceipt = redis.NewScript(1, `
if redis.call('TTL', KEYS[1]) < 1 or not redis.call('HGET', KEYS[1], 'token') then return 0 end
redis.call('HMSET', KEYS[1], 'confirmation_digest', ARGV[1])
return 1`)

type fileReceiptPayload struct {
	Issued int64            `json:"issued"`
	Salt   string           `json:"salt"`
	View   fileConfirmation `json:"view"`
}

func issueFileReceipt(id string, view fileConfirmation, now time.Time) (string, error) {
	payload, err := json.Marshal(fileReceiptPayload{Issued: now.Unix(), Salt: rand.Text(), View: view})
	if err != nil {
		return "", err
	}
	receipt := id + "." + base64.RawURLEncoding.EncodeToString(payload)
	if len(receipt) > maxFileReceiptBytes {
		return "", errFileReceiptUnavailable
	}
	digest := sha256.Sum256([]byte(receipt))
	conn := utils.NewPool().Get()
	defer conn.Close()
	attached, err := redis.Bool(attachFileReceipt.Do(conn, utils.REDIS_PREFIX+"file_"+id, digest[:]))
	if err != nil {
		return "", err
	}
	if !attached {
		return "", errFileReceiptUnavailable
	}
	return receipt, nil
}

func verifyFileReceipt(receipt string, now time.Time) (fileConfirmation, error) {
	if len(receipt) > maxFileReceiptBytes {
		return fileConfirmation{}, errFileReceiptUnavailable
	}
	id, encoded, ok := strings.Cut(receipt, ".")
	fileID, err := uuid.Parse(id)
	if !ok || encoded == "" || err != nil || fileID.String() != id {
		return fileConfirmation{}, errFileReceiptUnavailable
	}
	digest := sha256.Sum256([]byte(receipt))
	conn := utils.NewPool().Get()
	defer conn.Close()
	stored, err := redis.Bytes(conn.Do("HGET", utils.REDIS_PREFIX+"file_"+id, "confirmation_digest"))
	if err != nil && !errors.Is(err, redis.ErrNil) {
		return fileConfirmation{}, err
	}
	if subtle.ConstantTimeCompare(stored, digest[:]) != 1 {
		return fileConfirmation{}, errFileReceiptUnavailable
	}

	// Decode only an authenticated payload issued by this server. Neither a
	// confirmation nor a reload reserves a view or generates another alias.
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	var data fileReceiptPayload
	if err != nil || json.Unmarshal(payload, &data) != nil ||
		data.Issued > now.Unix() || data.Issued <= now.Add(-fileReceiptLifetime).Unix() {
		return fileConfirmation{}, errFileReceiptUnavailable
	}
	return data.View, nil
}

func ConfirmUploadedFile(c *echo.Context) error {
	c.Response().Header().Set("Cache-Control", "private, no-store")
	r := c.Request()
	contentType, _, err := mime.ParseMediaType(r.Header.Get(echo.HeaderContentType))
	if err != nil || contentType != echo.MIMEApplicationForm {
		return echo.ErrUnsupportedMediaType
	}
	// Read credentials only from the POST body, never from the URL.
	view, err := verifyFileReceipt(r.PostFormValue("receipt"), time.Now())
	if errors.Is(err, errFileReceiptUnavailable) {
		return echo.ErrNotFound
	}
	if err != nil {
		return echo.ErrServiceUnavailable
	}
	return view.render(c)
}
