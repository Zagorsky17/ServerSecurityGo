//go:build !unix

package fail2ban

import "io/fs"

// fileID — без inode файл узнаётся только по пути.
type fileID struct {
	dev, ino uint64
	path     string
}

func idOf(path string, _ fs.FileInfo) fileID { return fileID{path: path} }
