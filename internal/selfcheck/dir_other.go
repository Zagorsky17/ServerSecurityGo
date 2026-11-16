//go:build !unix

package selfcheck

import "os"

func openDirectory(path string) (*os.File, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, &os.PathError{Op: "open", Path: path, Err: os.ErrInvalid}
	}
	return os.Open(path)
}
