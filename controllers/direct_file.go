package controllers

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/gomodule/redigo/redis"
	"github.com/jeanphilippe-mh/Okuru/models"
	"github.com/jeanphilippe-mh/Okuru/utils"
	"github.com/labstack/echo/v5"
)

type directFileResponse struct {
	Link         string    `json:"link"`
	ExpiresAt    time.Time `json:"expires_at"`
	DeleteLink   string    `json:"delete_link,omitempty"`
	PasswordLink string    `json:"password_link,omitempty"`
}

func newDirectFileResponse(c *echo.Context, fileToken, passwordToken string, f *models.File, expiresAt time.Time) directFileResponse {
	origin, configured := shortLinkPublicOrigin(os.Getenv("OKURU_SHORTLINK_PUBLIC_ORIGIN"))
	response := directFileResponse{
		Link:      origin + sharePath(c, fileToken, true, configured),
		ExpiresAt: expiresAt,
	}
	if f.Deletable {
		response.DeleteLink = origin + "/file/remove/" + fileToken
	}
	if passwordToken != "" {
		response.PasswordLink = origin + sharePath(c, passwordToken, false, configured)
	}
	return response
}

func directFileExpiration(ctx context.Context, token string) (time.Time, error) {
	id, _, err := utils.ParseToken(token)
	if err != nil {
		return time.Time{}, err
	}
	conn, err := utils.NewPool().GetContext(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer conn.Close()
	key := utils.REDIS_PREFIX + "file_" + id
	// Redis 7+ can return its exact absolute expiration. On older Redis or
	// installations with restricted ACLs, estimate it from the remaining TTL.
	expiry, err := redis.Int64(redis.DoContext(conn, ctx, "PEXPIRETIME", key))
	if err == nil && expiry > 0 {
		return time.UnixMilli(expiry).UTC(), nil
	}
	if err != nil {
		var reply redis.Error
		if !errors.As(err, &reply) {
			return time.Time{}, err
		}
		ttl, err := redis.Int64(redis.DoContext(conn, ctx, "PTTL", key))
		if err != nil {
			return time.Time{}, err
		}
		if ttl > 0 {
			return time.Now().UTC().Add(time.Duration(ttl) * time.Millisecond).Truncate(time.Millisecond), nil
		}
	}
	return time.Time{}, errors.New("file expiration unavailable")
}
