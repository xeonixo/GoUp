package httpserver

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	systemWALWarnBytes = 256 << 20
	systemDBWarnBytes  = 1 << 30
)

// statDBFiles measures a SQLite database file plus its -wal and -shm companions. A missing main
// file is reported via Missing rather than as an error.
func statDBFiles(dataDir, label, path string) systemDBFileView {
	view := systemDBFileView{Label: label, RelPath: relativeToDataDir(dataDir, path)}
	mainSize, err := fileSize(path)
	if err != nil {
		view.Missing = true
		return view
	}
	walSize, _ := fileSize(path + "-wal")
	shmSize, _ := fileSize(path + "-shm")

	view.Size = formatByteSize(mainSize)
	view.WAL = formatByteSize(walSize)
	view.SHM = formatByteSize(shmSize)
	view.WALBytes = walSize
	view.TotalBytes = mainSize + walSize + shmSize
	view.LargeDB = mainSize > systemDBWarnBytes
	view.LargeWAL = walSize > systemWALWarnBytes
	return view
}

func fileSize(path string) (int64, error) {
	info, err := os.Stat(path)
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// relativeToDataDir shows path relative to the data dir when it lives inside it.
func relativeToDataDir(dataDir, path string) string {
	path = strings.TrimSpace(path)
	if dataDir == "" || path == "" {
		return path
	}
	rel, err := filepath.Rel(dataDir, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return filepath.Clean(path)
	}
	return rel
}
