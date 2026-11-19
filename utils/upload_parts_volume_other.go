//go:build !windows && !darwin && !linux

package utils

func checkUploadPartVolume(string, int64) error { return ErrStorageCapacity }
