//go:build unix

package httpserver

import "syscall"

// freeDiskBytes returns the bytes available to unprivileged users on the filesystem holding dir.
func freeDiskBytes(dir string) (uint64, bool) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		return 0, false
	}
	return uint64(stat.Bavail) * uint64(stat.Bsize), true
}
