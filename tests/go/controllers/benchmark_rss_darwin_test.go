//go:build darwin

package controllers

import "syscall"

func benchmarkPeakRSS() (int64, bool) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0, false
	}
	return usage.Maxrss, true
}
