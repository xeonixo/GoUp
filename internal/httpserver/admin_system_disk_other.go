//go:build !unix

package httpserver

// freeDiskBytes is not available on this platform.
func freeDiskBytes(string) (uint64, bool) {
	return 0, false
}
