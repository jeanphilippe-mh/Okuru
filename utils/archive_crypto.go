package utils

import (
	"context"
	"errors"
	"io"
	"sync"

	"filippo.io/age"
)

const ArchiveFormatAge = "age-v1"

// Use the highest work factor already accepted by the existing reader. This
// raises the cost of offline password guessing without changing the format or
// invalidating previously created factor-17 and factor-18 archives.
const archiveWriteWorkFactor = 18
const archiveMaxReadWorkFactor = 18

// Scrypt consumes roughly 256 MiB at factor 18. Bound concurrency locally and
// across processes using the same secured FILEFOLDER. Other hosts and services
// still need their own memory budgets.
var archiveKDF = make(chan struct{}, 1)

// ErrArchiveKDFBusy means the bounded KDF capacity is occupied.
// Callers must reject immediately rather than hold general request slots in an
// unbounded wait queue. The scrypt work factor is unchanged.
var ErrArchiveKDFBusy = errors.New("Archive password processing is busy")

type archiveKDFLeaseKey struct{}

type archiveKDFLease struct {
	mu     sync.Mutex
	active bool
}

// ReserveArchiveKDF reserves the single KDF slot without waiting. A controller
// can reserve before consuming a limited download view and pass the returned
// context to the archive reader. Release is idempotent and must always be called.
func ReserveArchiveKDF(ctx context.Context) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	select {
	case archiveKDF <- struct{}{}:
	default:
		return nil, nil, ErrArchiveKDFBusy
	}
	releaseProcessLock, busy, err := tryArchiveKDFProcessLock()
	if err != nil {
		<-archiveKDF
		return nil, nil, err
	}
	if busy {
		<-archiveKDF
		return nil, nil, ErrArchiveKDFBusy
	}
	if err := ctx.Err(); err != nil {
		releaseProcessLock()
		<-archiveKDF
		return nil, nil, err
	}
	lease := &archiveKDFLease{active: true}
	release := func() {
		lease.mu.Lock()
		defer lease.mu.Unlock()
		if lease.active {
			lease.active = false
			releaseProcessLock()
			<-archiveKDF
		}
	}
	return context.WithValue(ctx, archiveKDFLeaseKey{}, lease), release, nil
}

func withArchiveKDF(ctx context.Context, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if lease, ok := ctx.Value(archiveKDFLeaseKey{}).(*archiveKDFLease); ok {
		// Serialize use and release of a reserved slot so a stale or copied
		// context cannot start concurrent derivations after its slot is released.
		if !lease.mu.TryLock() {
			return ErrArchiveKDFBusy
		}
		defer lease.mu.Unlock()
		if !lease.active {
			return ErrArchiveKDFBusy
		}
		return fn()
	}
	_, release, err := ReserveArchiveKDF(ctx)
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

func EncryptArchive(ctx context.Context, dst io.Writer, password string) (io.WriteCloser, error) {
	recipient, err := age.NewScryptRecipient(password)
	if err != nil {
		return nil, err
	}
	recipient.SetWorkFactor(archiveWriteWorkFactor)
	var encrypted io.WriteCloser
	err = withArchiveKDF(ctx, func() error { var e error; encrypted, e = age.Encrypt(dst, recipient); return e })
	return encrypted, err
}

func DecryptArchive(ctx context.Context, src io.Reader, password string) (io.Reader, error) {
	identity, err := age.NewScryptIdentity(password)
	if err != nil {
		return nil, err
	}
	identity.SetMaxWorkFactor(archiveMaxReadWorkFactor)
	var plaintext io.Reader
	err = withArchiveKDF(ctx, func() error { var e error; plaintext, e = age.Decrypt(src, identity); return e })
	return plaintext, err
}
