package utils

import "io"

// UploadArchiveSource opens a single verified entry in a private staging area.
// The caller serializes readers against cancellation and deletion.
type UploadArchiveSource struct {
	Filename string
	Size     int64
	Open     func() (io.ReadCloser, error)
}
