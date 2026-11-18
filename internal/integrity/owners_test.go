package integrity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOwnersCompleteAndUnknown(t *testing.T) {
	root := t.TempDir()
	write := func(path, body string) {
		path = filepath.Join(root, path)
		os.MkdirAll(filepath.Dir(path), 0755)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("var/lib/dpkg/status", "Package: test\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n")
	write("var/lib/dpkg/info/test.list", "/usr/lib/libtest.so\n/etc/systemd/system/test.service\n/etc/init.d/test\n/usr/share/doc/test/copyright\n")
	if err := os.Symlink("usr/lib", filepath.Join(root, "lib")); err != nil {
		t.Fatal(err)
	}
	owners, err := Owners(root)
	if err != nil || !owners["/usr/lib/libtest.so"] || !owners["/lib/libtest.so"] || !owners["/etc/systemd/system/test.service"] || owners["/usr/share/doc/test/copyright"] {
		t.Fatalf("%v %v", owners, err)
	}
	write("var/lib/dpkg/info/test.list", "/usr/lib/libtest.so\n/../escape\n")
	owners, err = Owners(root)
	if err == nil || owners != nil {
		t.Fatal("partial database treated as complete")
	}
	os.Remove(filepath.Join(root, "var/lib/dpkg/info/test.list"))
	owners, err = Owners(root)
	if err == nil || owners != nil {
		t.Fatal("missing list treated as unowned")
	}
}

func TestOwnersForIncludesRequestedBinaryAndUsrMerge(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "var/lib/dpkg/info"), 0700)
	os.WriteFile(filepath.Join(root, "var/lib/dpkg/status"), []byte("Package: test\nStatus: install ok installed\nVersion: 1\nArchitecture: amd64\n"), 0600)
	os.WriteFile(filepath.Join(root, "var/lib/dpkg/info/test.list"), []byte("/bin/ping\n/usr/bin/other\n/usr/lib/test.so\n"), 0600)
	os.Symlink("usr/bin", filepath.Join(root, "bin"))
	combined, err := OwnersIncluding(root, map[string]bool{"/usr/bin/ping": true})
	if err != nil || !combined["/usr/bin/ping"] || !combined["/usr/lib/test.so"] || combined["/usr/bin/other"] {
		t.Fatal(combined, err)
	}
	got, e := OwnersFor(root, map[string]bool{"/usr/bin/ping": true})
	if e != nil || !got["/usr/bin/ping"] || got["/usr/bin/other"] || got["/usr/lib/test.so"] {
		t.Fatal(got, e)
	}
}
