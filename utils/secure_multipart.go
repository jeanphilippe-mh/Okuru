package utils

import (
	"context"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"

	"filippo.io/age"
)

// SecureMultipartFile is a bounded multipart file encrypted with a key that
// exists only in the request process. Names and file contents are never used
// as temporary filenames.
type SecureMultipartFile struct {
	Filename string
	Size     int64
	path     string
	identity *age.X25519Identity
	owner    *SecureMultipart
}

func (f *SecureMultipartFile) Open() (io.ReadCloser, error) {
	if f == nil || f.owner == nil {
		return nil, errors.New("multipart file has no owner")
	}
	if err := f.owner.acquireReader(); err != nil {
		return nil, err
	}
	handedOff := false
	defer func() {
		if !handedOff {
			f.owner.releaseReader()
		}
	}()
	guard, err := AcquireStoragePathGuard(filepath.Dir(f.path))
	if err != nil {
		return nil, err
	}
	in, err := OpenStorageArchive(f.path)
	if err != nil {
		_ = guard.Close()
		return nil, err
	}
	plain, err := age.Decrypt(in, f.identity)
	if err != nil {
		_ = in.Close()
		_ = guard.Close()
		return nil, err
	}
	handedOff = true
	return &secureMultipartReader{Reader: plain, file: in, guard: guard, owner: f.owner}, nil
}

type secureMultipartReader struct {
	io.Reader
	file  io.Closer
	guard *StoragePathGuard
	owner *SecureMultipart
	once  sync.Once
	err   error
}

func (r *secureMultipartReader) Close() error {
	r.once.Do(func() {
		r.err = errors.Join(r.file.Close(), r.guard.Close())
		if r.err == nil {
			r.owner.releaseReader()
		}
	})
	return r.err
}

type secureMultipartContextKey struct{}

type SecureMultipart struct {
	Files   []*SecureMultipartFile
	stage   *LockedStagingDir
	mu      sync.Mutex
	readers int
	closed  bool
}

func (f *SecureMultipart) Close() error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil
	}
	if f.readers != 0 {
		return errors.New("multipart readers are still open")
	}
	if f.stage != nil {
		if err := f.stage.Close(); err != nil {
			return err
		}
	}
	f.closed = true
	return nil
}

func (f *SecureMultipart) acquireReader() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return errors.New("multipart form is closed")
	}
	f.readers++
	return nil
}

func (f *SecureMultipart) releaseReader() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.readers--
}

func GetSecureMultipart(r *http.Request) *SecureMultipart {
	f, _ := r.Context().Value(secureMultipartContextKey{}).(*SecureMultipart)
	return f
}

var ErrSecureMultipart = errors.New("invalid multipart upload")
var ErrSecureMultipartTooLarge = errors.New("multipart upload exceeds its limit")

// ParseSecureMultipart never invokes net/http's form parser, which would spill
// plaintext to os.TempDir. It consumes the body once before CSRF extraction.
// Independent random public-key encryption bounds memory and permits any
// order of file, password, and CSRF fields without persisting plaintext.
func ParseSecureMultipart(r *http.Request, storageDir string, maxFileBytes int64, maxFiles int) (_ *SecureMultipart, resultErr error) {
	if existing := GetSecureMultipart(r); existing != nil {
		return existing, nil
	}
	if r.MultipartForm != nil || r.Form != nil || maxFileBytes <= 0 || maxFiles <= 0 {
		return nil, ErrSecureMultipart
	}
	mr, err := r.MultipartReader()
	if err != nil {
		return nil, ErrSecureMultipart
	}
	form := &SecureMultipart{}
	defer func() {
		if resultErr != nil {
			_ = form.Close()
		}
	}()
	values := make(url.Values)
	var identity *age.X25519Identity
	var total int64
	var fieldBytes int64
	fieldCount := 0
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Join(ErrSecureMultipart, err)
		}
		name, filename := part.FormName(), part.FileName()
		if len(name) == 0 || len(name) > 128 {
			return nil, ErrSecureMultipart
		}
		if filename == "" {
			fieldCount++
			if fieldCount > 32 {
				return nil, ErrSecureMultipart
			}
			value, err := io.ReadAll(io.LimitReader(part, MaxSecretBytes+1))
			fieldBytes += int64(len(value))
			if len(value) > MaxSecretBytes || fieldBytes > 128<<10 {
				return nil, errors.Join(ErrSecureMultipartTooLarge, err)
			}
			if err != nil {
				return nil, errors.Join(ErrSecureMultipart, err)
			}
			if err := part.Close(); err != nil {
				return nil, errors.Join(ErrSecureMultipart, err)
			}
			values[name] = append(values[name], string(value))
			continue
		}
		if name != "files" || len(filename) > 255 || len(form.Files) >= maxFiles {
			return nil, ErrSecureMultipart
		}
		if identity == nil {
			identity, err = age.GenerateX25519Identity()
			if err != nil {
				return nil, ErrSecureMultipart
			}
			form.stage, err = CreateLockedStagingDir(storageDir, ".okuru-multipart-")
			if err != nil {
				return nil, ErrSecureMultipart
			}
		}
		path := filepath.Join(form.stage.Path, fmt.Sprintf("%03d.age", len(form.Files)))
		out, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return nil, ErrSecureMultipart
		}
		encrypted, err := age.Encrypt(out, identity.Recipient())
		if err != nil {
			_ = out.Close()
			return nil, ErrSecureMultipart
		}
		n, copyErr := io.Copy(encrypted, io.LimitReader(part, maxFileBytes-total+1))
		finishErr := errors.Join(encrypted.Close(), out.Close())
		if n > maxFileBytes-total {
			return nil, errors.Join(ErrSecureMultipartTooLarge, copyErr, finishErr)
		}
		if copyErr != nil || finishErr != nil {
			return nil, errors.Join(ErrSecureMultipart, copyErr, finishErr)
		}
		// io.Copy reached the part's actual EOF, so Close cannot drain a
		// rejected or stalled request. Never close a partially read part.
		if err := part.Close(); err != nil {
			return nil, errors.Join(ErrSecureMultipart, err)
		}
		total += n
		form.Files = append(form.Files, &SecureMultipartFile{Filename: filename, Size: n, path: path, identity: identity, owner: form})
	}
	// Populate the net/http cache, so CSRF and downstream handlers cannot
	// reparse the original body with the standard disk-spilling parser.
	r.PostForm = values
	r.Form = make(url.Values, len(values))
	for k, v := range values {
		r.Form[k] = append([]string(nil), v...)
	}
	for k, v := range r.URL.Query() {
		r.Form[k] = append(r.Form[k], v...)
	}
	r.MultipartForm = &multipart.Form{Value: values, File: make(map[string][]*multipart.FileHeader)}
	*r = *r.WithContext(context.WithValue(r.Context(), secureMultipartContextKey{}, form))
	return form, nil
}
