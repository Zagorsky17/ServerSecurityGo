package procfs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestNetTablesCompleteRejectsMissingAndMalformed(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "net"), 0700)
	if NetTablesComplete(root) {
		t.Fatal("missing accepted")
	}
	for _, n := range []string{"tcp", "tcp6", "udp", "udp6"} {
		os.WriteFile(filepath.Join(root, "net", n), []byte("sl local_address rem_address st\n"), 0600)
	}
	if !NetTablesComplete(root) {
		t.Fatal("empty valid tables rejected")
	}
	os.WriteFile(filepath.Join(root, "net/tcp"), []byte("sl local_address rem_address st\nmalformed\n"), 0600)
	if NetTablesComplete(root) {
		t.Fatal("malformed accepted")
	}
}
