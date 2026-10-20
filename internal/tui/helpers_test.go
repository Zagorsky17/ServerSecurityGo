package tui

import (
	"os"
	"testing"
)

// makeShortTempDir создаёт каталог с коротким путём для Unix-сокета:
// t.TempDir() на macOS длиннее лимита sun_path (104 байта).
func makeShortTempDir(t *testing.T) (string, error) {
	dir, err := os.MkdirTemp("/tmp", "ssg")
	if err != nil {
		return "", err
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir, nil
}
