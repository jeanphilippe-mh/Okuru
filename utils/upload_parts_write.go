package utils

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"filippo.io/age"
)

// Bind each ciphertext to its position. A misplaced, otherwise authentic age
// file cannot substitute data at another offset or in another manifest entry.
func (p uploadPart) header() [16]byte {
	var h [16]byte
	binary.BigEndian.PutUint64(h[:8], uint64(p.index))
	binary.BigEndian.PutUint64(h[8:], uint64(p.start))
	return h
}

func (set *uploadPartSet) remember(p uploadPart) {
	set.files[p.index] = append(set.files[p.index], p)
	set.count++
	set.pending = nil
}

// A transport failure after Redis executed the CAS must not unlink committed
// bytes. Retain the sealed candidate and replay that exact CAS before accepting
// another write. Only an authenticated, confirmed position adopts the block.
func (set *uploadPartSet) reconcile(ctx context.Context, id, bearer string) error {
	p := set.pending
	if p == nil {
		return nil
	}
	pos, err := ConfirmedUploadOffset(ctx, id, bearer, p.index)
	if err != nil {
		return err
	}
	if pos == p.end {
		set.remember(*p)
		return nil
	}
	if pos != p.start {
		return uploadSessionError("unavailable")
	}
	if err := CommitUploadOffset(ctx, id, bearer, p.index, p.start, p.end); err != nil {
		return err
	}
	set.remember(*p)
	return nil
}

func getUploadParts(s *UploadSession) (*uploadPartSet, error) {
	if s == nil || s.Metadata == nil || s.Mode != "blocks" {
		return nil, uploadSessionError("wrong_mode")
	}
	set := localPartSet(s.ID)
	if set == nil || set.generation != sessionGeneration() {
		return nil, uploadSessionError("unavailable")
	}
	return set, nil
}

// Caller holds the per-session lock. No original filenames, bearer tokens,
// passwords, plaintext chunks or age identities are written into the staging area.
func AppendUploadPart(ctx context.Context, s *UploadSession, bearer string, index int, offset, declared, limit int64, body io.Reader) (int64, error) {
	set, err := getUploadParts(s)
	if err != nil {
		return 0, err
	}
	if index < 0 || index >= len(set.files) {
		return 0, uploadSessionError("not_found")
	}
	if s.State != "open" && s.State != "receiving" {
		return 0, uploadSessionError("busy")
	}
	if err := set.reconcile(ctx, s.ID, bearer); err != nil {
		return 0, err
	}
	pos, err := ConfirmedUploadOffset(ctx, s.ID, bearer, index)
	if err != nil {
		return 0, err
	}
	if pos != offset {
		return pos, uploadSessionError("offset_conflict")
	}
	if limit <= 0 {
		return pos, uploadSessionError("unavailable")
	}
	limit = min(limit, s.Metadata.Files[index].Size-pos)
	if limit < 0 || declared > limit {
		return pos, uploadSessionError("too_large")
	}
	if body == nil {
		return pos, uploadSessionError("invalid_request")
	}
	// Probe one byte first so empty PATCHes are inexpensive and cannot consume
	// the bounded journal or leave a staging file.
	var first [1]byte
	n, err := io.ReadFull(body, first[:])
	if n == 0 && errors.Is(err, io.EOF) {
		if declared > 0 {
			return pos, uploadSessionError("invalid_request")
		}
		return pos, nil
	}
	if err != nil {
		return pos, uploadReadError(err)
	}
	if limit == 0 {
		return pos, uploadSessionError("too_large")
	}
	if set.count >= maxUploadParts {
		return pos, uploadSessionError("part_limit")
	}
	tmp, err := os.CreateTemp(set.dir, ".receiving-")
	if err != nil {
		return pos, ErrStorageCapacity
	}
	defer os.Remove(tmp.Name())
	sealed, err := age.Encrypt(tmp, set.identity.Recipient())
	if err != nil {
		_ = tmp.Close()
		return pos, ErrStorageCapacity
	}
	p := uploadPart{index: index, start: pos}
	header := p.header()
	_, err = sealed.Write(header[:])
	if err == nil {
		_, err = sealed.Write(first[:])
	}
	observed := int64(1)
	if err == nil {
		var buf [32 << 10]byte
		nextTouch := time.Now().Add(time.Minute)
		for {
			if err = ctx.Err(); err != nil {
				break
			}
			// Read at most one byte beyond the permitted body.
			got, readErr := body.Read(buf[:min(int64(len(buf)), limit-observed+1)])
			if got > 0 {
				observed += int64(got)
				if observed > limit {
					err = uploadSessionError("too_large")
					break
				}
				if _, err = sealed.Write(buf[:got]); err != nil {
					err = ErrStorageCapacity
					break
				}
				if time.Now().After(nextTouch) {
					if err = TouchUploadSession(ctx, s.ID, bearer); err != nil {
						break
					}
					nextTouch = time.Now().Add(time.Minute)
				}
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil || got == 0 {
				err = uploadReadError(readErr)
				break
			}
		}
	}
	if err == nil && declared >= 0 && observed != declared {
		err = uploadSessionError("invalid_request")
	}
	closeErr := sealed.Close()
	if err == nil {
		if closeErr != nil || tmp.Sync() != nil {
			err = ErrStorageCapacity
		}
	}
	if closeErr = tmp.Close(); err == nil && closeErr != nil {
		err = ErrStorageCapacity
	}
	if err != nil {
		return pos, err
	}
	p.end = pos + observed
	p.path = filepath.Join(set.dir, fmt.Sprintf("%d-%d.age", index, pos))
	if err = os.Link(tmp.Name(), p.path); err != nil {
		return pos, ErrStorageCapacity
	}
	if err = syncPublicationDir(set.dir); err != nil {
		_ = os.Remove(p.path)
		return pos, ErrStorageCapacity
	}
	set.pending = &p
	if err = CommitUploadOffset(ctx, s.ID, bearer, index, p.start, p.end); err != nil {
		// These own-session rejections are definitive. A connection error may
		// have followed the commit; reconciliation must retain its witness.
		if _, code := UploadSessionHTTPError(err); code == "part_limit" || code == "busy" || code == "expired" || code == "aborted" || code == "interrupted" {
			if removeErr := os.Remove(p.path); removeErr == nil {
				set.pending = nil
			}
		}
		return pos, err
	}
	set.remember(p)
	return p.end, nil
}
