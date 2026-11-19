package utils

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fernet/fernet-go"
	"github.com/google/uuid"
)

const UploadSessionManifestLimit = 64 << 10
const UploadSessionMaxFiles = 100

type UploadManifest struct {
	Mode     string
	Metadata DirectFileMetadata
}

type UploadSession struct {
	ID, Mode, State string
	Metadata        *DirectFileMetadata
	Bytes, Total    int64
	ExpiresAt       time.Time
	StatusOnly      bool
	StatusToken     string
}

type uploadSessionError string

func (e uploadSessionError) Error() string { return string(e) }

func UploadSessionHTTPError(err error) (int, string) {
	var code uploadSessionError
	if !errors.As(err, &code) {
		return http.StatusServiceUnavailable, "unavailable"
	}
	switch code {
	case "invalid_manifest", "invalid_id", "invalid_request":
		return 400, string(code)
	case "not_found":
		return 404, string(code)
	case "expired", "aborted", "interrupted":
		return 410, string(code)
	case "manifest_conflict", "wrong_mode", "busy", "already_ready", "not_ready", "part_limit", "offset_conflict":
		return 409, string(code)
	case "too_large":
		return 413, string(code)
	case "capacity", "rate_limit":
		return 429, string(code)
	default:
		return 503, string(code)
	}
}

func UploadBearer(r *http.Request) string {
	if r == nil || len(r.Header.Values("Authorization")) != 1 {
		return ""
	}
	scheme, value, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || !validUploadSecret(value) {
		return ""
	}
	return value
}

func validUploadSecret(s string) bool {
	if len(s) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	return err == nil && len(b) == 32 && base64.RawURLEncoding.EncodeToString(b) == s
}
func validUploadID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id.Version() == 4 && id.Variant() == uuid.RFC4122 && id.String() == s
}

func ParseUploadManifest(r io.Reader, maxBytes int64) (*UploadManifest, error) {
	if r == nil || maxBytes <= 0 {
		return nil, uploadSessionError("invalid_manifest")
	}
	data, err := io.ReadAll(io.LimitReader(r, UploadSessionManifestLimit+1))
	if len(data) > UploadSessionManifestLimit {
		return nil, uploadSessionError("too_large")
	}
	if err != nil || !utf8.Valid(data) {
		return nil, uploadSessionError("invalid_manifest")
	}
	m := &UploadManifest{Metadata: DirectFileMetadata{TTLSeconds: 3600, Views: 1}}
	var rawFiles json.RawMessage
	if !decodeDirectObject(data, map[string]any{"mode": &m.Mode, "ttl_seconds": &m.Metadata.TTLSeconds, "views": &m.Metadata.Views, "deletable": &m.Metadata.Deletable, "password": &m.Metadata.Password, "files": &rawFiles}) ||
		(m.Mode != "multipart" && m.Mode != "blocks") || ValidateAPILimits(m.Metadata.TTLSeconds, m.Metadata.Views) != nil {
		return nil, uploadSessionError("invalid_manifest")
	}
	if ValidateSecretLength(m.Metadata.Password) != nil {
		return nil, uploadSessionError("too_large")
	}
	d := json.NewDecoder(bytes.NewReader(rawFiles))
	start, err := d.Token()
	if err != nil || start != json.Delim('[') {
		return nil, uploadSessionError("invalid_manifest")
	}
	var total int64
	seen := map[string]bool{}
	for d.More() {
		if len(m.Metadata.Files) >= UploadSessionMaxFiles {
			return nil, uploadSessionError("too_large")
		}
		var raw json.RawMessage
		f := DirectFileSpec{Size: -1}
		if d.Decode(&raw) != nil || !decodeDirectObject(raw, map[string]any{"name": &f.Name, "size": &f.Size}) || f.Size < 0 {
			return nil, uploadSessionError("invalid_manifest")
		}
		key, ok := UploadFilenameKey(f.Name)
		if !ok || seen[key] {
			return nil, uploadSessionError("invalid_manifest")
		}
		if f.Size > maxBytes-total {
			return nil, uploadSessionError("too_large")
		}
		total += f.Size
		seen[key] = true
		m.Metadata.Files = append(m.Metadata.Files, f)
	}
	end, err := d.Token()
	if err != nil || end != json.Delim(']') || len(m.Metadata.Files) == 0 {
		return nil, uploadSessionError("invalid_manifest")
	}
	return m, nil
}

func uploadDigest(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
func uploadMAC(secret, domain string, data []byte) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(secret)
	mac := hmac.New(sha256.New, b)
	mac.Write([]byte(domain))
	mac.Write([]byte{0})
	mac.Write(data)
	return mac.Sum(nil)
}
func uploadEnvelopeKey(id, bearer, purpose string) *fernet.Key {
	var key fernet.Key
	copy(key[:], uploadMAC(bearer, "okuru/upload-v2/"+purpose, []byte(id)))
	return &key
}
func sealUpload(id, bearer, purpose string, data []byte) ([]byte, error) {
	return fernet.EncryptAndSign(data, uploadEnvelopeKey(id, bearer, purpose))
}
func openUpload(id, bearer, purpose string, blob []byte) ([]byte, error) {
	plain := fernet.VerifyAndDecrypt(blob, 0, []*fernet.Key{uploadEnvelopeKey(id, bearer, purpose)})
	if plain == nil {
		return nil, uploadSessionError("unavailable")
	}
	return plain, nil
}
func newUploadSecret() string {
	var b [32]byte
	rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
