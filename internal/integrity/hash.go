package integrity

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"time"

	"github.com/Zagorsky17/ServerSecurityGo/internal/i18n"
	"github.com/Zagorsky17/ServerSecurityGo/internal/safefile"
)

var errChanged = i18n.Errorf("err.integrity_file_changed")

type digest struct{ MD5, SHA256 string }
type readerBudget struct {
	start       time.Time
	bytes, rate int64
}

func (b *readerBudget) hash(ctx context.Context, root *os.Root, name string) (digest, error) {
	var out digest
	if err := ctx.Err(); err != nil {
		return out, err
	}
	f, before, err := safefile.OpenRooted(root, name)
	if err != nil {
		return out, err
	}
	defer f.Close()
	if before.Size() > 1<<30 {
		return out, safefile.ErrTooLarge
	}
	md, sha := md5.New(), sha256.New()
	buf := make([]byte, 64<<10)
	var size int64
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		n, err := f.Read(buf)
		if n > 0 {
			size += int64(n)
			if size > 1<<30 {
				return out, safefile.ErrTooLarge
			}
			md.Write(buf[:n])
			sha.Write(buf[:n])
			b.bytes += int64(n)
			if b.rate > 0 {
				if err := wait(ctx, time.Until(b.start.Add(time.Duration(float64(b.bytes)/float64(b.rate)*float64(time.Second))))); err != nil {
					return out, err
				}
			}
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return out, err
		}
	}
	after, err := f.Stat()
	if err != nil {
		return out, err
	}
	current, err := root.Lstat(name)
	if err != nil {
		return out, errChanged
	}
	if size != before.Size() || size != after.Size() || !before.ModTime().Equal(after.ModTime()) || !os.SameFile(before, current) || !current.Mode().IsRegular() || !current.ModTime().Equal(before.ModTime()) {
		return out, errChanged
	}
	return digest{hex.EncodeToString(md.Sum(nil)), hex.EncodeToString(sha.Sum(nil))}, nil
}
func wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
