package utils

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gomodule/redigo/redis"
)

func UploadSessionRedisKeys(id string) (string, string) {
	p := REDIS_PREFIX + "upload_v2_"
	return p + id, p + "index"
}

func uploadChunksEnabled() bool {
	enabled, _ := strconv.ParseBool(os.Getenv("OKURU_UPLOAD_CHUNKS"))
	return enabled && UploadPatchLimit() > 0
}

func UploadAdmission(ctx context.Context) (bool, bool, error) {
	if sessionGeneration() == "" {
		return false, false, uploadSessionError("unavailable")
	}
	c, err := NewPool().GetContext(ctx)
	if err != nil {
		return false, false, err
	}
	defer c.Close()
	result, err := redis.Strings(redis.DoContext(c, ctx, "HMGET", REDIS_PREFIX+"upload_v2_admission", "api", "blocks"))
	if err != nil || len(result) != 2 {
		return false, false, uploadSessionError("unavailable")
	}
	api := result[0] == "open"
	return api, api && result[1] == "open" && uploadChunksEnabled(), nil
}

func uploadCommand(ctx context.Context, id, op, proof string, args ...any) ([]string, error) {
	gen := sessionGeneration()
	if gen == "" {
		return nil, uploadSessionError("unavailable")
	}
	c, err := NewPool().GetContext(ctx)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	key, idx := UploadSessionRedisKeys(id)
	params := []any{key, idx, REDIS_PREFIX + "upload_v2_admission", id, gen, op, proof}
	result, err := redis.Strings(uploadSessionScript.DoContext(ctx, c, append(params, args...)...))
	if err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, uploadSessionError("unavailable")
	}
	switch result[0] {
	case "ok", "created", "replay":
		return result, nil
	default:
		return nil, uploadSessionError(result[0])
	}
}

func sessionAccess(ctx context.Context, id, bearer, op string, args ...any) ([]string, error) {
	if !validUploadID(id) || !validUploadSecret(bearer) {
		return nil, uploadSessionError("not_found")
	}
	return uploadCommand(ctx, id, op, uploadDigest(bearer), args...)
}

func ReconcileUploadSessions(ctx context.Context) error {
	_, err := uploadCommand(ctx, "", "sweep", "", REDIS_PREFIX+"upload_v2_")
	return err
}

// UploadSessionOwnsParts is for the service's staging collector. A Redis
// failure is distinct from a confirmed terminal session; preserve disk state
// until ownership has been checked successfully.
func UploadSessionOwnsParts(ctx context.Context, id string) (bool, error) {
	if !validUploadID(id) {
		return false, uploadSessionError("invalid_id")
	}
	v, err := uploadCommand(ctx, id, "owns_parts", "")
	if err != nil {
		return false, err
	}
	if len(v) != 2 {
		return false, uploadSessionError("unavailable")
	}
	return v[1] == "1", nil
}

// TouchUploadSession refreshes inactivity after a real body read. Callers
// throttle refreshes; status and HEAD do not use it.
func TouchUploadSession(ctx context.Context, id, bearer string) error {
	_, err := sessionAccess(ctx, id, bearer, "touch")
	return err
}

type privateUploadSession struct {
	Metadata    DirectFileMetadata
	StatusToken string
}

func PrepareFileUploadSession(ctx context.Context, r *http.Request, id, bearer string, m *UploadManifest) (*UploadSession, bool, error) {
	if !validUploadID(id) {
		return nil, false, uploadSessionError("invalid_id")
	}
	if !validUploadSecret(bearer) {
		return nil, false, uploadSessionError("not_found")
	}
	identity, err := ClientIdentity(r)
	if err != nil {
		return nil, false, uploadSessionError("unavailable")
	}
	identityDigest := uploadDigest(identity)
	activeIdentity := identityDigest
	if SharedClientIdentity(identity) {
		activeIdentity = ""
		identityDigest = "shared"
	}
	budget, err := redisSecretMaxKeys()
	if err != nil {
		return nil, false, err
	}
	if m == nil || len(m.Metadata.Files) == 0 || len(m.Metadata.Files) > UploadSessionMaxFiles {
		return nil, false, uploadSessionError("invalid_manifest")
	}
	normalized, err := json.Marshal(m)
	if err != nil {
		return nil, false, err
	}
	status := newUploadSecret()
	payload, err := json.Marshal(privateUploadSession{m.Metadata, status})
	if err != nil {
		return nil, false, err
	}
	envelope, err := sealUpload(id, bearer, "manifest", payload)
	if err != nil {
		return nil, false, err
	}
	var total int64
	for _, f := range m.Metadata.Files {
		if f.Size < 0 || f.Size > MaxFileSize-total {
			return nil, false, uploadSessionError("too_large")
		}
		total += f.Size
	}
	args := []any{m.Mode, hex.EncodeToString(uploadMAC(bearer, "manifest", normalized)), uploadDigest(status), envelope, total, activeIdentity, budget, uploadChunksEnabled(), REDIS_PREFIX + "upload_v2_", len(m.Metadata.Files), identityDigest}
	for _, f := range m.Metadata.Files {
		args = append(args, f.Size)
	}
	result, err := sessionAccess(ctx, id, bearer, "create", args...)
	if err != nil {
		return nil, false, err
	}
	s, err := AuthorizeUploadSession(ctx, id, bearer, false)
	return s, result[0] == "created", err
}

func AuthorizeUploadSession(ctx context.Context, id, bearer string, allowStatus bool) (*UploadSession, error) {
	watch := "0"
	if allowStatus {
		watch = "1"
	}
	v, err := sessionAccess(ctx, id, bearer, "read", watch)
	if err != nil {
		return nil, err
	}
	if len(v) != 9 {
		return nil, uploadSessionError("unavailable")
	}
	n, e1 := strconv.ParseInt(v[3], 10, 64)
	total, e2 := strconv.ParseInt(v[4], 10, 64)
	expiry, e3 := strconv.ParseInt(v[5], 10, 64)
	bodyTotal, e4 := strconv.ParseInt(v[6], 10, 64)
	if errors.Join(e1, e2, e3, e4) != nil {
		return nil, uploadSessionError("unavailable")
	}
	s := &UploadSession{ID: id, Mode: v[2], State: v[1], Bytes: n, Total: total, ExpiresAt: time.UnixMilli(expiry).UTC(), StatusOnly: v[8] != "1"}
	if s.Mode == "multipart" {
		s.Total = bodyTotal
	}
	if !s.StatusOnly {
		plain, err := openUpload(id, bearer, "manifest", []byte(v[7]))
		if err != nil {
			return nil, err
		}
		var secret privateUploadSession
		if json.Unmarshal(plain, &secret) != nil || !validUploadSecret(secret.StatusToken) {
			return nil, uploadSessionError("unavailable")
		}
		s.Metadata = &secret.Metadata
		s.StatusToken = secret.StatusToken
	}
	return s, nil
}

func BeginMultipartAttempt(ctx context.Context, id, bearer string, total int64) error {
	if total < -1 {
		return uploadSessionError("invalid_request")
	}
	_, err := sessionAccess(ctx, id, bearer, "begin_multipart", total)
	return err
}
func SetMultipartProgress(ctx context.Context, id, bearer string, n int64) error {
	if n < 0 {
		return uploadSessionError("invalid_request")
	}
	_, err := sessionAccess(ctx, id, bearer, "progress", n)
	return err
}
func ResetUploadAttempt(ctx context.Context, id, bearer string) error {
	_, err := sessionAccess(ctx, id, bearer, "reset")
	return err
}
func AbortFileUploadSession(ctx context.Context, id, bearer string) error {
	_, err := sessionAccess(ctx, id, bearer, "abort")
	return err
}
func RejectUploadReservation(ctx context.Context, id, bearer string) error {
	_, err := sessionAccess(ctx, id, bearer, "reject_reservation")
	return err
}
func ConfirmedUploadOffset(ctx context.Context, id, bearer string, index int) (int64, error) {
	if index < 0 || index >= UploadSessionMaxFiles {
		return 0, uploadSessionError("not_found")
	}
	values, err := sessionAccess(ctx, id, bearer, "offset", index)
	if err != nil {
		return 0, err
	}
	if len(values) != 2 {
		return 0, uploadSessionError("unavailable")
	}
	return strconv.ParseInt(values[1], 10, 64)
}
func CommitUploadOffset(ctx context.Context, id, bearer string, index int, old, newOffset int64) error {
	if index < 0 || index >= UploadSessionMaxFiles {
		return uploadSessionError("not_found")
	}
	if old < 0 || newOffset < old {
		return uploadSessionError("offset_conflict")
	}
	_, err := sessionAccess(ctx, id, bearer, "append", index, old, newOffset)
	return err
}
func BeginUploadPublication(ctx context.Context, id, bearer string) error {
	_, err := sessionAccess(ctx, id, bearer, "begin_publication")
	return err
}
func RevertUploadPublication(ctx context.Context, id, bearer string) error {
	_, err := sessionAccess(ctx, id, bearer, "revert_finalizing")
	return err
}
func BindUploadPublication(ctx context.Context, id, bearer, publicationID string) error {
	if !validUploadID(publicationID) {
		return uploadSessionError("invalid_id")
	}
	_, err := sessionAccess(ctx, id, bearer, "bind", publicationID)
	return err
}
func SealUploadResult(id, bearer string, result []byte) ([]byte, error) {
	if !validUploadID(id) || !validUploadSecret(bearer) || len(result) > UploadSessionManifestLimit || !json.Valid(result) {
		return nil, uploadSessionError("invalid_request")
	}
	return sealUpload(id, bearer, "result", result)
}
func StoreSealedUploadResult(ctx context.Context, id, expectedPublicationID string, sealed []byte, expires time.Time) error {
	if !validUploadID(id) || !validUploadID(expectedPublicationID) || len(sealed) == 0 {
		return uploadSessionError("invalid_request")
	}
	_, err := uploadCommand(ctx, id, "commit_sealed", "", expectedPublicationID, sealed, expires.UnixMilli())
	return err
}
func InterruptUploadPublication(ctx context.Context, id, expectedPublicationID string) error {
	if !validUploadID(id) || !validUploadID(expectedPublicationID) {
		return uploadSessionError("invalid_request")
	}
	_, err := uploadCommand(ctx, id, "interrupt_publication", "", expectedPublicationID)
	return err
}
func ReadUploadResult(ctx context.Context, id, bearer string) ([]byte, error) {
	v, err := sessionAccess(ctx, id, bearer, "result")
	if err != nil {
		return nil, err
	}
	if len(v) != 3 {
		return nil, uploadSessionError("unavailable")
	}
	payload, err := openUpload(id, bearer, "result", []byte(v[1]))
	if err != nil {
		return nil, err
	}
	expiry, err := strconv.ParseInt(v[2], 10, 64)
	if err != nil {
		return nil, uploadSessionError("unavailable")
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(payload, &result) != nil || result == nil {
		return nil, uploadSessionError("unavailable")
	}
	deadline, _ := json.Marshal(time.UnixMilli(expiry).UTC())
	result["expires_at"] = deadline
	return json.Marshal(result)
}
