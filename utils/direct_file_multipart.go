package utils

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"unicode/utf8"
)

const maxDirectMetadataBytes = 64 << 10

// DirectFileMetadata contains validated options and the ordered files declared
// in the first part of a direct multipart upload.
type DirectFileMetadata struct {
	TTLSeconds int
	Views      int
	Deletable  bool
	Password   string
	Files      []DirectFileSpec
}

type DirectFileSpec struct {
	Name string
	Size int64
}

// A short read in a MIME header can become a syntax error in net/textproto.
// Preserve the transport error so the HTTP layer can still recognize its
// request-size limit or a disconnect.
type directMultipartBody struct {
	io.ReadCloser
	readErr error
}

func (body *directMultipartBody) Read(p []byte) (int, error) {
	n, err := body.ReadCloser.Read(p)
	if err != nil && err != io.EOF && body.readErr == nil {
		body.readErr = err
	}
	return n, err
}

func readDirectFileMetadata(r *http.Request, mr *multipart.Reader, maxFileBytes int64, maxFiles int) (*DirectFileMetadata, error) {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || len(r.Header.Values("Content-Type")) != 1 || mediaType != "multipart/form-data" {
		return nil, ErrSecureMultipart
	}
	part, err := mr.NextRawPart()
	if err != nil || len(part.Header.Values("Content-Disposition")) != 1 || part.FormName() != "metadata" {
		return nil, errors.Join(ErrSecureMultipart, err)
	}
	mediaType, params, err := mime.ParseMediaType(part.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" || len(part.Header.Values("Content-Type")) != 1 ||
		len(part.Header.Values("Content-Transfer-Encoding")) != 0 {
		return nil, ErrSecureMultipart
	}
	if charset, ok := params["charset"]; ok && !strings.EqualFold(charset, "utf-8") {
		return nil, ErrSecureMultipart
	}
	data, err := io.ReadAll(io.LimitReader(part, maxDirectMetadataBytes+1))
	if len(data) > maxDirectMetadataBytes {
		return nil, ErrSecureMultipartTooLarge
	}
	if err != nil {
		return nil, errors.Join(ErrSecureMultipart, err)
	}
	if !utf8.Valid(data) {
		return nil, ErrSecureMultipart
	}
	var m DirectFileMetadata
	var rawFiles json.RawMessage
	fields := map[string]any{
		"ttl_seconds": &m.TTLSeconds,
		"views":       &m.Views,
		"deletable":   &m.Deletable,
		"password":    &m.Password,
		"files":       &rawFiles,
	}
	if !decodeDirectObject(data, fields) || ValidateAPILimits(m.TTLSeconds, m.Views) != nil {
		return nil, ErrSecureMultipart
	}
	if ValidateSecretLength(m.Password) != nil {
		return nil, ErrSecureMultipartTooLarge
	}
	// Stop at the first excess entry without allocating a slice proportional
	// to the number of JSON values that fit inside the metadata byte limit.
	files := json.NewDecoder(bytes.NewReader(rawFiles))
	start, err := files.Token()
	if err != nil || start != json.Delim('[') {
		return nil, ErrSecureMultipart
	}
	names := make(map[string]bool)
	var total int64
	for files.More() {
		if len(m.Files) >= maxFiles {
			return nil, ErrSecureMultipartTooLarge
		}
		var raw json.RawMessage
		spec := DirectFileSpec{Size: -1}
		if files.Decode(&raw) != nil || !decodeDirectObject(raw, map[string]any{"name": &spec.Name, "size": &spec.Size}) || spec.Size < 0 {
			return nil, ErrSecureMultipart
		}
		key, valid := UploadFilenameKey(spec.Name)
		if !valid || names[key] {
			return nil, errors.Join(ErrSecureMultipart, ErrSecureMultipartFilename)
		}
		if spec.Size > maxFileBytes-total {
			return nil, ErrSecureMultipartTooLarge
		}
		names[key] = true
		total += spec.Size
		m.Files = append(m.Files, spec)
	}
	end, err := files.Token()
	if err != nil || end != json.Delim(']') || len(m.Files) == 0 {
		return nil, ErrSecureMultipart
	}
	return &m, nil
}

// Require exact case-sensitive keys. Removing each destination after use also
// rejects repeated keys, even when their spellings use different JSON escapes.
func decodeDirectObject(data []byte, fields map[string]any) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return false
	}
	for dec.More() {
		key, err := dec.Token()
		name, ok := key.(string)
		dst := fields[name]
		if err != nil || !ok || dst == nil {
			return false
		}
		var raw json.RawMessage
		if dec.Decode(&raw) != nil || bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, dst) != nil {
			return false
		}
		delete(fields, name)
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return false
	}
	_, err = dec.Token()
	return err == io.EOF
}

func directPartMatches(part *multipart.Part, filename string) bool {
	if len(part.Header.Values("Content-Disposition")) != 1 || len(part.Header.Values("Content-Transfer-Encoding")) != 0 {
		return false
	}
	// Part.FileName strips path components. Compare the original parameter
	// exactly, so an undeclared path cannot silently become a declared basename.
	disposition, params, err := mime.ParseMediaType(part.Header.Get("Content-Disposition"))
	return err == nil && disposition == "form-data" && params["filename"] == filename
}
