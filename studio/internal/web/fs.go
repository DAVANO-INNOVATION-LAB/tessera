package web

import (
	"io/fs"
	"os"
	"sort"
)

// readDirSorted lists a directory with directories first, then names, so the
// UI's ordering is stable between requests rather than filesystem-dependent.
func readDirSorted(dir string) ([]os.DirEntry, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return entries[i].Name() < entries[j].Name()
	})
	return entries, nil
}

// statFile returns file info for the analysis target.
func statFile(path string) (fs.FileInfo, error) {
	return os.Stat(path)
}
