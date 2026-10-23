//go:build !unix

package sqlite

import "math"

// freeDiskSpace is not implemented on this platform; the vacuum space check is skipped.
func freeDiskSpace(string) (uint64, error) {
	return math.MaxUint64, nil
}
