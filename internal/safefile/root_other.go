//go:build !unix

package safefile

import "os"

func readFlags() int { return os.O_RDONLY }
func openDir(path string) (*os.File, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, ErrNotRegular
	}
	return os.Open(path)
}
