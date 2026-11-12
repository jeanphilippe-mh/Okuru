//go:build !linux && !darwin

package controllers

func benchmarkPeakRSS() (int64, bool) { return 0, false }
