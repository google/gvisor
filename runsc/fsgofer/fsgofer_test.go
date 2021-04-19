// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package fsgofer

import (
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/p9"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Nodoby is the standard UID/GID for the nobody user/group.
const nobody = 65534

var allOpenFlags = []p9.OpenFlags{p9.ReadOnly, p9.WriteOnly, p9.ReadWrite}

var (
	allTypes = []uint32{unix.S_IFREG, unix.S_IFDIR, unix.S_IFLNK}

	// allConfs is set in init().
	allConfs []Config

	rwConfs = []Config{{ROMount: false}}
	roConfs = []Config{{ROMount: true}}
)

func init() {
	log.SetLevel(log.Debug)

	allConfs = append(allConfs, rwConfs...)
	allConfs = append(allConfs, roConfs...)

	if err := OpenProcSelfFD(); err != nil {
		panic(err)
	}
}

func configTestName(conf *Config) string {
	if conf.ROMount {
		return "ROMount"
	}
	return "RWMount"
}

func assertPanic(t *testing.T, f func()) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("function did not panic")
		}
	}()
	f()
}

func testReadWrite(f p9.File, flags p9.OpenFlags, content []byte) error {
	want := make([]byte, len(content))
	copy(want, content)

	b := []byte("test-1-2-3")
	w, err := f.WriteAt(b, uint64(len(content)))
	if flags == p9.WriteOnly || flags == p9.ReadWrite {
		if err != nil {
			return fmt.Errorf("WriteAt(): %v", err)
		}
		if w != len(b) {
			return fmt.Errorf("WriteAt() was partial, got: %d, want: %d", w, len(b))
		}
		want = append(want, b...)
	} else {
		if e, ok := err.(unix.Errno); !ok || e != unix.EBADF {
			return fmt.Errorf("WriteAt() should have failed, got: %d, want: EBADFD", err)
		}
	}

	rBuf := make([]byte, len(want))
	r, err := f.ReadAt(rBuf, 0)
	if flags == p9.ReadOnly || flags == p9.ReadWrite {
		if err != nil {
			return fmt.Errorf("ReadAt(): %v", err)
		}
		if r != len(rBuf) {
			return fmt.Errorf("ReadAt() was partial, got: %d, want: %d", r, len(rBuf))
		}
		if string(rBuf) != string(want) {
			return fmt.Errorf("ReadAt() wrong data, got: %s, want: %s", string(rBuf), want)
		}
	} else {
		if e, ok := err.(unix.Errno); !ok || e != unix.EBADF {
			return fmt.Errorf("ReadAt() should have failed, got: %d, want: EBADFD", err)
		}
	}
	return nil
}

type state struct {
	root     *localFile
	file     *localFile
	conf     Config
	fileType uint32
}

func (s state) String() string {
	return fmt.Sprintf("type(%v)", s.fileType)
}

func typeName(fileType uint32) string {
	switch fileType {
	case unix.S_IFREG:
		return "file"
	case unix.S_IFDIR:
		return "directory"
	case unix.S_IFLNK:
		return "symlink"
	default:
		panic(fmt.Sprintf("invalid file type for test: %d", fileType))
	}
}

func runAll(t *testing.T, test func(*testing.T, state)) {
	runCustom(t, allTypes, allConfs, test)
}

func runCustom(t *testing.T, types []uint32, confs []Config, test func(*testing.T, state)) {
	for _, c := range confs {
		for _, ft := range types {
			name := fmt.Sprintf("%s/%s", configTestName(&c), typeName(ft))
			t.Run(name, func(t *testing.T) {
				path, name, err := setup(ft)
				if err != nil {
					t.Fatalf("%v", err)
				}
				defer os.RemoveAll(path)

				a, err := NewAttachPoint(path, c)
				if err != nil {
					t.Fatalf("NewAttachPoint failed: %v", err)
				}
				root, err := a.Attach()
				if err != nil {
					t.Fatalf("Attach failed, err: %v", err)
				}

				_, file, err := root.Walk([]string{name})
				if err != nil {
					root.Close()
					t.Fatalf("root.Walk({%q}) failed, err: %v", "symlink", err)
				}

				st := state{
					root:     root.(*localFile),
					file:     file.(*localFile),
					conf:     c,
					fileType: ft,
				}
				test(t, st)
				file.Close()
				root.Close()
			})
		}
	}
}

func setup(fileType uint32) (string, string, error) {
	path, err := ioutil.TempDir(testutil.TmpDir(), "root-")
	if err != nil {
		return "", "", fmt.Errorf("ioutil.TempDir() failed, err: %v", err)
	}

	// First attach with writable configuration to setup tree.
	a, err := NewAttachPoint(path, Config{})
	if err != nil {
		return "", "", err
	}
	root, err := a.Attach()
	if err != nil {
		return "", "", fmt.Errorf("Attach failed, err: %v", err)
	}
	defer root.Close()

	var name string
	switch fileType {
	case unix.S_IFREG:
		name = "file"
		fd, f, _, _, err := root.Create(name, p9.ReadWrite, 0777, p9.UID(os.Getuid()), p9.GID(os.Getgid()))
		if err != nil {
			return "", "", fmt.Errorf("createFile(root, %q) failed, err: %v", "test", err)
		}
		if fd != nil {
			fd.Close()
		}
		defer f.Close()
	case unix.S_IFDIR:
		name = "dir"
		if _, err := root.Mkdir(name, 0777, p9.UID(os.Getuid()), p9.GID(os.Getgid())); err != nil {
			return "", "", fmt.Errorf("root.MkDir(%q) failed, err: %v", name, err)
		}
	case unix.S_IFLNK:
		name = "symlink"
		if _, err := root.Symlink("/some/target", name, p9.UID(os.Getuid()), p9.GID(os.Getgid())); err != nil {
			return "", "", fmt.Errorf("root.Symlink(%q) failed, err: %v", name, err)
		}
	default:
		panic(fmt.Sprintf("unknown file type %v", fileType))
	}
	return path, name, nil
}

func createFile(dir *localFile, name string) (*localFile, error) {
	_, f, _, _, err := dir.Create(name, p9.ReadWrite, 0777, p9.UID(os.Getuid()), p9.GID(os.Getgid()))
	if err != nil {
		return nil, err
	}
	return f.(*localFile), nil
}

func TestReadWrite(t *testing.T) {
	runCustom(t, []uint32{unix.S_IFDIR}, rwConfs, func(t *testing.T, s state) {
		child, err := createFile(s.file, "test")
		if err != nil {
			t.Fatalf("%v: createFile() failed, err: %v", s, err)
		}
		defer child.Close()
		want := []byte("foobar")
		w, err := child.WriteAt(want, 0)
		if err != nil {
			t.Fatalf("%v: Write() failed, err: %v", s, err)
		}
		if w != len(want) {
			t.Fatalf("%v: Write() was partial, got: %d, expected: %d", s, w, len(want))
		}
		for _, flags := range allOpenFlags {
			_, l, err := s.file.Walk([]string{"test"})
			if err != nil {
				t.Fatalf("%v: Walk(%s) failed, err: %v", s, "test", err)
			}
			fd, _, _, err := l.Open(flags)
			if err != nil {
				t.Fatalf("%v: Open(%v) failed, err: %v", s, flags, err)
			}
			if fd != nil {
				defer fd.Close()
			}
			if err := testReadWrite(l, flags, want); err != nil {
				t.Fatalf("%v: testReadWrite(%v) failed: %v", s, flags, err)
			}
		}
	})
}

func TestCreate(t *testing.T) {
	runCustom(t, []uint32{unix.S_IFDIR}, rwConfs, func(t *testing.T, s state) {
		for i, flags := range allOpenFlags {
			_, l, _, _, err := s.file.Create(fmt.Sprintf("test-%d", i), flags, 0777, p9.UID(os.Getuid()), p9.GID(os.Getgid()))
			if err != nil {
				t.Fatalf("%v, %v: WriteAt() failed, err: %v", s, flags, err)
			}

			if err := testReadWrite(l, flags, nil); err != nil {
				t.Fatalf("%v: testReadWrite(%v) failed: %v", s, flags, err)
			}
		}
	})
}

func checkIDs(f p9.File, uid, gid int) error {
	_, _, stat, err := f.GetAttr(p9.AttrMask{UID: true, GID: true})
	if err != nil {
		return fmt.Errorf("GetAttr() failed, err: %v", err)
	}
	if want := p9.UID(uid); stat.UID != want {
		return fmt.Errorf("Wrong UID, want: %v, got: %v", want, stat.UID)
	}
	if want := p9.GID(gid); stat.GID != want {
		return fmt.Errorf("Wrong GID, want: %v, got: %v", want, stat.GID)
	}
	return nil
}

// TestCreateSetGID checks files/dirs/symlinks are created with the proper
// owner when the parent directory has setgid set,
func TestCreateSetGID(t *testing.T) {
	if !specutils.HasCapabilities(capability.CAP_CHOWN) {
		t.Skipf("Test requires CAP_CHOWN")
	}

	runCustom(t, []uint32{unix.S_IFDIR}, rwConfs, func(t *testing.T, s state) {
		// Change group and set setgid to the parent dir.
		if err := unix.Chown(s.file.hostPath, os.Getuid(), nobody); err != nil {
			t.Fatalf("Chown() failed: %v", err)
		}
		if err := unix.Chmod(s.file.hostPath, 02777); err != nil {
			t.Fatalf("Chmod() failed: %v", err)
		}

		t.Run("create", func(t *testing.T) {
			_, l, _, _, err := s.file.Create("test", p9.ReadOnly, 0777, p9.UID(os.Getuid()), p9.GID(os.Getgid()))
			if err != nil {
				t.Fatalf("WriteAt() failed: %v", err)
			}
			defer l.Close()
			if err := checkIDs(l, os.Getuid(), os.Getgid()); err != nil {
				t.Error(err)
			}
		})

		t.Run("mkdir", func(t *testing.T) {
			_, err := s.file.Mkdir("test-dir", 0777, p9.UID(os.Getuid()), p9.GID(os.Getgid()))
			if err != nil {
				t.Fatalf("WriteAt() failed: %v", err)
			}
			_, l, err := s.file.Walk([]string{"test-dir"})
			if err != nil {
				t.Fatalf("Walk() failed: %v", err)
			}
			defer l.Close()
			if err := checkIDs(l, os.Getuid(), os.Getgid()); err != nil {
				t.Error(err)
			}
		})

		t.Run("symlink", func(t *testing.T) {
			if _, err := s.file.Symlink("/some/target", "symlink", p9.UID(os.Getuid()), p9.GID(os.Getgid())); err != nil {
				t.Fatalf("Symlink() failed: %v", err)
			}
			_, l, err := s.file.Walk([]string{"symlink"})
			if err != nil {
				t.Fatalf("Walk() failed, err: %v", err)
			}
			defer l.Close()
			if err := checkIDs(l, os.Getuid(), os.Getgid()); err != nil {
				t.Error(err)
			}
		})

		t.Run("mknod", func(t *testing.T) {
			if _, err := s.file.Mknod("nod", p9.ModeRegular|0777, 0, 0, p9.UID(os.Getuid()), p9.GID(os.Getgid())); err != nil {
				t.Fatalf("Mknod() failed: %v", err)
			}
			_, l, err := s.file.Walk([]string{"nod"})
			if err != nil {
				t.Fatalf("Walk() failed, err: %v", err)
			}
			defer l.Close()
			if err := checkIDs(l, os.Getuid(), os.Getgid()); err != nil {
				t.Error(err)
			}
		})
	})
}

// TestReadWriteDup tests that a file opened in any mode can be dup'ed and
// reopened in any other mode.
func TestReadWriteDup(t *testing.T) {
	runCustom(t, []uint32{unix.S_IFDIR}, rwConfs, func(t *testing.T, s state) {
		child, err := createFile(s.file, "test")
		if err != nil {
			t.Fatalf("%v: createFile() failed, err: %v", s, err)
		}
		defer child.Close()
		want := []byte("foobar")
		w, err := child.WriteAt(want, 0)
		if err != nil {
			t.Fatalf("%v: Write() failed, err: %v", s, err)
		}
		if w != len(want) {
			t.Fatalf("%v: Write() was partial, got: %d, expected: %d", s, w, len(want))
		}
		for _, flags := range allOpenFlags {
			_, l, err := s.file.Walk([]string{"test"})
			if err != nil {
				t.Fatalf("%v: Walk(%s) failed, err: %v", s, "test", err)
			}
			defer l.Close()
			if _, _, _, err := l.Open(flags); err != nil {
				t.Fatalf("%v: Open(%v) failed, err: %v", s, flags, err)
			}
			for _, dupFlags := range allOpenFlags {
				t.Logf("Original flags: %v, dup flags: %v", flags, dupFlags)
				_, dup, err := l.Walk([]string{})
				if err != nil {
					t.Fatalf("%v: Walk(<empty>) failed: %v", s, err)
				}
				defer dup.Close()
				fd, _, _, err := dup.Open(dupFlags)
				if err != nil {
					t.Fatalf("%v: Open(%v) failed: %v", s, flags, err)
				}
				if fd != nil {
					defer fd.Close()
				}
				if err := testReadWrite(dup, dupFlags, want); err != nil {
					t.Fatalf("%v: testReadWrite(%v) failed: %v", s, dupFlags, err)
				}
			}
		}
	})
}

func TestUnopened(t *testing.T) {
	runCustom(t, []uint32{unix.S_IFREG}, allConfs, func(t *testing.T, s state) {
		b := []byte("foobar")
		if _, err := s.file.WriteAt(b, 0); err != unix.EBADF {
			t.Errorf("%v: WriteAt() should have failed, got: %v, expected: unix.EBADF", s, err)
		}
		if _, err := s.file.ReadAt(b, 0); err != unix.EBADF {
			t.Errorf("%v: ReadAt() should have failed, got: %v, expected: unix.EBADF", s, err)
		}
		if _, err := s.file.Readdir(0, 100); err != unix.EBADF {
			t.Errorf("%v: Readdir() should have failed, got: %v, expected: unix.EBADF", s, err)
		}
		if err := s.file.FSync(); err != unix.EBADF {
			t.Errorf("%v: FSync() should have failed, got: %v, expected: unix.EBADF", s, err)
		}
	})
}

// TestOpenOPath is a regression test to ensure that a file that cannot be open
// for read is allowed to be open. This was happening because the control file
// was open with O_PATH, but Open() was not checking for it and allowing the
// control file to be reused.
func TestOpenOPath(t *testing.T) {
	runCustom(t, []uint32{unix.S_IFREG}, rwConfs, func(t *testing.T, s state) {
		// Fist remove all permissions on the file.
		if err := s.file.SetAttr(p9.SetAttrMask{Permissions: true}, p9.SetAttr{Permissions: p9.FileMode(0)}); err != nil {
			t.Fatalf("SetAttr(): %v", err)
		}
		// Then walk to the file again to open a new control file.
		filename := filepath.Base(s.file.hostPath)
		_, newFile, err := s.root.Walk([]string{filename})
		if err != nil {
			t.Fatalf("root.Walk(%q): %v", filename, err)
		}

		if newFile.(*localFile).controlReadable {
			t.Fatalf("control file didn't open with O_PATH: %+v", newFile)
		}
		if _, _, _, err := newFile.Open(p9.ReadOnly); err != unix.EACCES {
			t.Fatalf("Open() should have failed, got: %v, wanted: EACCES", err)
		}
	})
}

func SetGetAttr(l *localFile, valid p9.SetAttrMask, attr p9.SetAttr) (p9.Attr, error) {
	if err := l.SetAttr(valid, attr); err != nil {
		return p9.Attr{}, err
	}
	_, _, a, err := l.GetAttr(p9.AttrMask{})
	if err != nil {
		return p9.Attr{}, err
	}
	return a, nil
}

func TestSetAttrPerm(t *testing.T) {
	runCustom(t, allTypes, rwConfs, func(t *testing.T, s state) {
		valid := p9.SetAttrMask{Permissions: true}
		attr := p9.SetAttr{Permissions: 0777}
		got, err := SetGetAttr(s.file, valid, attr)
		if s.fileType == unix.S_IFLNK {
			if err == nil {
				t.Fatalf("%v: SetGetAttr(valid, %v) should have failed", s, attr.Permissions)
			}
		} else {
			if err != nil {
				t.Fatalf("%v: SetGetAttr(valid, %v) failed, err: %v", s, attr.Permissions, err)
			}
			if got.Mode.Permissions() != attr.Permissions {
				t.Errorf("%v: wrong permission, got: %v, expected: %v", s, got.Mode.Permissions(), attr.Permissions)
			}
		}
	})
}

func TestSetAttrSize(t *testing.T) {
	runCustom(t, allTypes, rwConfs, func(t *testing.T, s state) {
		for _, size := range []uint64{1024, 0, 1024 * 1024} {
			valid := p9.SetAttrMask{Size: true}
			attr := p9.SetAttr{Size: size}
			got, err := SetGetAttr(s.file, valid, attr)
			if s.fileType == unix.S_IFLNK || s.fileType == unix.S_IFDIR {
				if err == nil {
					t.Fatalf("%v: SetGetAttr(valid, %v) should have failed", s, attr.Permissions)
				}
				// Run for one size only, they will all fail the same way.
				return
			}
			if err != nil {
				t.Fatalf("%v: SetGetAttr(valid, %v) failed, err: %v", s, attr.Size, err)
			}
			if got.Size != size {
				t.Errorf("%v: wrong size, got: %v, expected: %v", s, got.Size, size)
			}
		}
	})
}

func TestSetAttrTime(t *testing.T) {
	runCustom(t, allTypes, rwConfs, func(t *testing.T, s state) {
		valid := p9.SetAttrMask{ATime: true, ATimeNotSystemTime: true}
		attr := p9.SetAttr{ATimeSeconds: 123, ATimeNanoSeconds: 456}
		got, err := SetGetAttr(s.file, valid, attr)
		if err != nil {
			t.Fatalf("%v: SetGetAttr(valid, %v:%v) failed, err: %v", s, attr.ATimeSeconds, attr.ATimeNanoSeconds, err)
		}
		if got.ATimeSeconds != 123 {
			t.Errorf("%v: wrong ATimeSeconds, got: %v, expected: %v", s, got.ATimeSeconds, 123)
		}
		if got.ATimeNanoSeconds != 456 {
			t.Errorf("%v: wrong ATimeNanoSeconds, got: %v, expected: %v", s, got.ATimeNanoSeconds, 456)
		}

		valid = p9.SetAttrMask{MTime: true, MTimeNotSystemTime: true}
		attr = p9.SetAttr{MTimeSeconds: 789, MTimeNanoSeconds: 012}
		got, err = SetGetAttr(s.file, valid, attr)
		if err != nil {
			t.Fatalf("%v: SetGetAttr(valid, %v:%v) failed, err: %v", s, attr.MTimeSeconds, attr.MTimeNanoSeconds, err)
		}
		if got.MTimeSeconds != 789 {
			t.Errorf("%v: wrong MTimeSeconds, got: %v, expected: %v", s, got.MTimeSeconds, 789)
		}
		if got.MTimeNanoSeconds != 012 {
			t.Errorf("%v: wrong MTimeNanoSeconds, got: %v, expected: %v", s, got.MTimeNanoSeconds, 012)
		}
	})
}

func TestSetAttrOwner(t *testing.T) {
	if !specutils.HasCapabilities(capability.CAP_CHOWN) {
		t.Skipf("SetAttr(owner) test requires CAP_CHOWN, running as %d", os.Getuid())
	}

	runCustom(t, allTypes, rwConfs, func(t *testing.T, s state) {
		newUID := os.Getuid() + 1
		valid := p9.SetAttrMask{UID: true}
		attr := p9.SetAttr{UID: p9.UID(newUID)}
		got, err := SetGetAttr(s.file, valid, attr)
		if err != nil {
			t.Fatalf("%v: SetGetAttr(valid, %v) failed, err: %v", s, attr.UID, err)
		}
		if got.UID != p9.UID(newUID) {
			t.Errorf("%v: wrong uid, got: %v, expected: %v", s, got.UID, newUID)
		}
	})
}

func SetGetXattr(l *localFile, name string, value string) error {
	if err := l.SetXattr(name, value, 0 /* flags */); err != nil {
		return err
	}
	ret, err := l.GetXattr(name, uint64(len(value)))
	if err != nil {
		return err
	}
	if ret != value {
		return fmt.Errorf("Got value %s, want %s", ret, value)
	}
	return nil
}

func TestSetGetDisabledXattr(t *testing.T) {
	runCustom(t, []uint32{unix.S_IFREG}, rwConfs, func(t *testing.T, s state) {
		name := "user.merkle.offset"
		value := "tmp"
		err := SetGetXattr(s.file, name, value)
		if err == nil {
			t.Fatalf("%v: SetGetXattr should have failed", s)
		}
	})
}

func TestSetGetXattr(t *testing.T) {
	runCustom(t, []uint32{unix.S_IFREG}, []Config{{ROMount: false, EnableVerityXattr: true}}, func(t *testing.T, s state) {
		name := "user.merkle.offset"
		value := "tmp"
		err := SetGetXattr(s.file, name, value)
		if err != nil {
			t.Fatalf("%v: SetGetXattr failed, err: %v", s, err)
		}
	})
}

func TestLink(t *testing.T) {
	if !specutils.HasCapabilities(capability.CAP_DAC_READ_SEARCH) {
		t.Skipf("Link test requires CAP_DAC_READ_SEARCH, running as %d", os.Getuid())
	}
	runCustom(t, allTypes, rwConfs, func(t *testing.T, s state) {
		const dirName = "linkdir"
		const linkFile = "link"
		if _, err := s.root.Mkdir(dirName, 0777, p9.UID(os.Getuid()), p9.GID(os.Getgid())); err != nil {
			t.Fatalf("%v: MkDir(%s) failed, err: %v", s, dirName, err)
		}
		_, dir, err := s.root.Walk([]string{dirName})
		if err != nil {
			t.Fatalf("%v: Walk({%s}) failed, err: %v", s, dirName, err)
		}

		err = dir.Link(s.file, linkFile)
		if s.fileType == unix.S_IFDIR {
			if err != unix.EPERM {
				t.Errorf("%v: Link(target, %s) should have failed, got: %v, expected: unix.EPERM", s, linkFile, err)
			}
			return
		}
		if err != nil {
			t.Errorf("%v: Link(target, %s) failed, err: %v", s, linkFile, err)
		}
	})
}

func TestROMountChecks(t *testing.T) {
	const want = unix.EROFS
	uid := p9.UID(os.Getuid())
	gid := p9.GID(os.Getgid())

	runCustom(t, allTypes, roConfs, func(t *testing.T, s state) {
		if s.fileType != unix.S_IFLNK {
			if _, _, _, err := s.file.Open(p9.WriteOnly); err != want {
				t.Errorf("Open() should have failed, got: %v, expected: %v", err, want)
			}
			if _, _, _, err := s.file.Open(p9.ReadWrite); err != want {
				t.Errorf("Open() should have failed, got: %v, expected: %v", err, want)
			}
			if _, _, _, err := s.file.Open(p9.ReadOnly | p9.OpenTruncate); err != want {
				t.Errorf("Open() should have failed, got: %v, expected: %v", err, want)
			}
			f, _, _, err := s.file.Open(p9.ReadOnly)
			if err != nil {
				t.Errorf("Open() failed: %v", err)
			}
			if f != nil {
				_ = f.Close()
			}
		}

		if _, _, _, _, err := s.file.Create("some_file", p9.ReadWrite, 0777, uid, gid); err != want {
			t.Errorf("Create() should have failed, got: %v, expected: %v", err, want)
		}
		if _, err := s.file.Mkdir("some_dir", 0777, uid, gid); err != want {
			t.Errorf("MkDir() should have failed, got: %v, expected: %v", err, want)
		}
		if err := s.file.RenameAt("some_file", s.file, "other_file"); err != want {
			t.Errorf("Rename() should have failed, got: %v, expected: %v", err, want)
		}
		if _, err := s.file.Symlink("some_place", "some_symlink", uid, gid); err != want {
			t.Errorf("Symlink() should have failed, got: %v, expected: %v", err, want)
		}
		if err := s.file.UnlinkAt("some_file", 0); err != want {
			t.Errorf("UnlinkAt() should have failed, got: %v, expected: %v", err, want)
		}
		if err := s.file.Link(s.file, "some_link"); err != want {
			t.Errorf("Link() should have failed, got: %v, expected: %v", err, want)
		}
		if _, err := s.file.Mknod("some-nod", 0777, 1, 2, uid, gid); err != want {
			t.Errorf("Mknod() should have failed, got: %v, expected: %v", err, want)
		}

		valid := p9.SetAttrMask{Size: true}
		attr := p9.SetAttr{Size: 0}
		if err := s.file.SetAttr(valid, attr); err != want {
			t.Errorf("SetAttr() should have failed, got: %v, expected: %v", err, want)
		}
	})
}

func TestWalkNotFound(t *testing.T) {
	runCustom(t, []uint32{unix.S_IFDIR}, allConfs, func(t *testing.T, s state) {
		if _, _, err := s.file.Walk([]string{"nobody-here"}); err != unix.ENOENT {
			t.Errorf("Walk(%q) should have failed, got: %v, expected: unix.ENOENT", "nobody-here", err)
		}
		if _, _, err := s.file.Walk([]string{"nobody", "here"}); err != unix.ENOENT {
			t.Errorf("Walk(%q) should have failed, got: %v, expected: unix.ENOENT", "nobody/here", err)
		}
		if !s.conf.ROMount {
			if _, err := s.file.Mkdir("dir", 0777, p9.UID(os.Getuid()), p9.GID(os.Getgid())); err != nil {
				t.Fatalf("MkDir(dir) failed, err: %v", err)
			}
			if _, _, err := s.file.Walk([]string{"dir", "nobody-here"}); err != unix.ENOENT {
				t.Errorf("Walk(%q) should have failed, got: %v, expected: unix.ENOENT", "dir/nobody-here", err)
			}
		}
	})
}

func TestWalkDup(t *testing.T) {
	runAll(t, func(t *testing.T, s state) {
		_, dup, err := s.file.Walk([]string{})
		if err != nil {
			t.Fatalf("%v: Walk(nil) failed, err: %v", s, err)
		}
		// Check that 'dup' is usable.
		if _, _, _, err := dup.GetAttr(p9.AttrMask{}); err != nil {
			t.Errorf("%v: GetAttr() failed, err: %v", s, err)
		}
	})
}

func TestWalkMultiple(t *testing.T) {
	runCustom(t, []uint32{unix.S_IFDIR}, rwConfs, func(t *testing.T, s state) {
		var names []string
		var parent p9.File = s.file
		for i := 0; i < 5; i++ {
			name := fmt.Sprintf("dir%d", i)
			names = append(names, name)

			if _, err := parent.Mkdir(name, 0777, p9.UID(os.Getuid()), p9.GID(os.Getgid())); err != nil {
				t.Fatalf("MkDir(%q) failed, err: %v", name, err)
			}

			var err error
			_, parent, err = s.file.Walk(names)
			if err != nil {
				t.Errorf("Walk(%q): %v", name, err)
			}
		}
	})
}

func TestReaddir(t *testing.T) {
	runCustom(t, []uint32{unix.S_IFDIR}, rwConfs, func(t *testing.T, s state) {
		name := "dir"
		if _, err := s.file.Mkdir(name, 0777, p9.UID(os.Getuid()), p9.GID(os.Getgid())); err != nil {
			t.Fatalf("%v: MkDir(%s) failed, err: %v", s, name, err)
		}
		name = "symlink"
		if _, err := s.file.Symlink("/some/target", name, p9.UID(os.Getuid()), p9.GID(os.Getgid())); err != nil {
			t.Fatalf("%v: Symlink(%q) failed, err: %v", s, name, err)
		}
		name = "file"
		_, f, _, _, err := s.file.Create(name, p9.ReadWrite, 0555, p9.UID(os.Getuid()), p9.GID(os.Getgid()))
		if err != nil {
			t.Fatalf("%v: createFile(root, %q) failed, err: %v", s, name, err)
		}
		f.Close()

		if _, _, _, err := s.file.Open(p9.ReadOnly); err != nil {
			t.Fatalf("%v: Open(ReadOnly) failed, err: %v", s, err)
		}

		dirents, err := s.file.Readdir(0, 10)
		if err != nil {
			t.Fatalf("%v: Readdir(0, 10) failed, err: %v", s, err)
		}
		if len(dirents) != 3 {
			t.Fatalf("%v: Readdir(0, 10) wrong number of items, got: %v, expected: 3", s, len(dirents))
		}
		var dir, symlink, file bool
		for _, d := range dirents {
			switch d.Name {
			case "dir":
				if d.Type != p9.TypeDir {
					t.Errorf("%v: dirent.Type got: %v, expected: %v", s, d.Type, p9.TypeDir)
				}
				dir = true
			case "symlink":
				if d.Type != p9.TypeSymlink {
					t.Errorf("%v: dirent.Type got: %v, expected: %v", s, d.Type, p9.TypeSymlink)
				}
				symlink = true
			case "file":
				if d.Type != p9.TypeRegular {
					t.Errorf("%v: dirent.Type got: %v, expected: %v", s, d.Type, p9.TypeRegular)
				}
				file = true
			default:
				t.Errorf("%v: dirent.Name got: %v", s, d.Name)
			}

			_, f, err := s.file.Walk([]string{d.Name})
			if err != nil {
				t.Fatalf("%v: Walk({%s}) failed, err: %v", s, d.Name, err)
			}
			_, _, a, err := f.GetAttr(p9.AttrMask{})
			if err != nil {
				t.Fatalf("%v: GetAttr() failed, err: %v", s, err)
			}
			if d.Type != a.Mode.QIDType() {
				t.Errorf("%v: dirent.Type different than GetAttr().Mode.QIDType(), got: %v, expected: %v", s, d.Type, a.Mode.QIDType())
			}
		}
		if !dir || !symlink || !file {
			t.Errorf("%v: Readdir(0, 10) wrong files returned, dir: %v, symlink: %v, file: %v", s, dir, symlink, file)
		}
	})
}

// Test that attach point can be written to when it points to a file, e.g.
// /etc/hosts.
func TestAttachFile(t *testing.T) {
	conf := Config{ROMount: false}
	dir, err := ioutil.TempDir("", "root-")
	if err != nil {
		t.Fatalf("ioutil.TempDir() failed, err: %v", err)
	}
	defer os.RemoveAll(dir)

	path := path.Join(dir, "test")
	if _, err := os.Create(path); err != nil {
		t.Fatalf("os.Create(%q) failed, err: %v", path, err)
	}

	a, err := NewAttachPoint(path, conf)
	if err != nil {
		t.Fatalf("NewAttachPoint failed: %v", err)
	}
	root, err := a.Attach()
	if err != nil {
		t.Fatalf("Attach failed, err: %v", err)
	}

	if _, _, _, err := root.Open(p9.ReadWrite); err != nil {
		t.Fatalf("Open(ReadWrite) failed, err: %v", err)
	}
	defer root.Close()

	b := []byte("foobar")
	w, err := root.WriteAt(b, 0)
	if err != nil {
		t.Fatalf("Write() failed, err: %v", err)
	}
	if w != len(b) {
		t.Fatalf("Write() was partial, got: %d, expected: %d", w, len(b))
	}
	rBuf := make([]byte, len(b))
	r, err := root.ReadAt(rBuf, 0)
	if err != nil {
		t.Fatalf("ReadAt() failed, err: %v", err)
	}
	if r != len(rBuf) {
		t.Fatalf("ReadAt() was partial, got: %d, expected: %d", r, len(rBuf))
	}
	if string(rBuf) != "foobar" {
		t.Fatalf("ReadAt() wrong data, got: %s, expected: %s", string(rBuf), "foobar")
	}
}

func TestAttachInvalidType(t *testing.T) {
	dir, err := ioutil.TempDir("", "attach-")
	if err != nil {
		t.Fatalf("ioutil.TempDir() failed, err: %v", err)
	}
	defer os.RemoveAll(dir)

	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0755); err != nil {
		t.Fatalf("Mkfifo(%q): %v", fifo, err)
	}

	dirFile, err := os.Open(dir)
	if err != nil {
		t.Fatalf("Open(%s): %v", dir, err)
	}
	defer dirFile.Close()

	// Bind a socket via /proc to be sure that a length of a socket path
	// is less than UNIX_PATH_MAX.
	socket := filepath.Join(fmt.Sprintf("/proc/self/fd/%d", dirFile.Fd()), "socket")
	l, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatalf("net.Listen(unix, %q): %v", socket, err)
	}
	defer l.Close()

	for _, tc := range []struct {
		name string
		path string
	}{
		{name: "fifo", path: fifo},
		{name: "socket", path: socket},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conf := Config{ROMount: false}
			a, err := NewAttachPoint(tc.path, conf)
			if err != nil {
				t.Fatalf("NewAttachPoint failed: %v", err)
			}
			f, err := a.Attach()
			if f != nil || err == nil {
				t.Fatalf("Attach should have failed, got (%v, %v)", f, err)
			}
		})
	}
}

func TestDoubleAttachError(t *testing.T) {
	conf := Config{ROMount: false}
	root, err := ioutil.TempDir("", "root-")
	if err != nil {
		t.Fatalf("ioutil.TempDir() failed, err: %v", err)
	}
	defer os.RemoveAll(root)
	a, err := NewAttachPoint(root, conf)
	if err != nil {
		t.Fatalf("NewAttachPoint failed: %v", err)
	}

	if _, err := a.Attach(); err != nil {
		t.Fatalf("Attach failed: %v", err)
	}
	if _, err := a.Attach(); err == nil {
		t.Fatalf("Attach should have failed, got %v want non-nil", err)
	}
}

func TestTruncate(t *testing.T) {
	runCustom(t, []uint32{unix.S_IFDIR}, rwConfs, func(t *testing.T, s state) {
		child, err := createFile(s.file, "test")
		if err != nil {
			t.Fatalf("createFile() failed: %v", err)
		}
		defer child.Close()
		want := []byte("foobar")
		w, err := child.WriteAt(want, 0)
		if err != nil {
			t.Fatalf("Write() failed: %v", err)
		}
		if w != len(want) {
			t.Fatalf("Write() was partial, got: %d, expected: %d", w, len(want))
		}

		_, l, err := s.file.Walk([]string{"test"})
		if err != nil {
			t.Fatalf("Walk(%s) failed: %v", "test", err)
		}
		if _, _, _, err := l.Open(p9.ReadOnly | p9.OpenTruncate); err != nil {
			t.Fatalf("Open() failed: %v", err)
		}
		_, mask, attr, err := l.GetAttr(p9.AttrMask{Size: true})
		if err != nil {
			t.Fatalf("GetAttr() failed: %v", err)
		}
		if !mask.Size {
			t.Fatalf("GetAttr() didn't return size: %+v", mask)
		}
		if attr.Size != 0 {
			t.Fatalf("truncate didn't work, want: 0, got: %d", attr.Size)
		}
	})
}

func TestMknod(t *testing.T) {
	runCustom(t, []uint32{unix.S_IFDIR}, rwConfs, func(t *testing.T, s state) {
		_, err := s.file.Mknod("test", p9.ModeRegular|0777, 1, 2, p9.UID(os.Getuid()), p9.GID(os.Getgid()))
		if err != nil {
			t.Fatalf("Mknod() failed: %v", err)
		}

		_, f, err := s.file.Walk([]string{"test"})
		if err != nil {
			t.Fatalf("Walk() failed: %v", err)
		}
		fd, _, _, err := f.Open(p9.ReadWrite)
		if err != nil {
			t.Fatalf("Open() failed: %v", err)
		}
		if fd != nil {
			defer fd.Close()
		}
		if err := testReadWrite(f, p9.ReadWrite, nil); err != nil {
			t.Fatalf("testReadWrite() failed: %v", err)
		}
	})
}

func BenchmarkWalkOne(b *testing.B) {
	path, name, err := setup(unix.S_IFDIR)
	if err != nil {
		b.Fatalf("%v", err)
	}
	defer os.RemoveAll(path)

	a, err := NewAttachPoint(path, Config{})
	if err != nil {
		b.Fatalf("NewAttachPoint failed: %v", err)
	}
	root, err := a.Attach()
	if err != nil {
		b.Fatalf("Attach failed, err: %v", err)
	}
	defer root.Close()

	names := []string{name}
	files := make([]p9.File, 0, 1000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, file, err := root.Walk(names)
		if err != nil {
			b.Fatalf("Walk(%q): %v", name, err)
		}
		files = append(files, file)

		// Avoid running out of FDs.
		if len(files) == cap(files) {
			b.StopTimer()
			for _, file := range files {
				file.Close()
			}
			files = files[:0]
			b.StartTimer()
		}
	}

	b.StopTimer()
	for _, file := range files {
		file.Close()
	}
}

func BenchmarkCreate(b *testing.B) {
	path, _, err := setup(unix.S_IFDIR)
	if err != nil {
		b.Fatalf("%v", err)
	}
	defer os.RemoveAll(path)

	a, err := NewAttachPoint(path, Config{})
	if err != nil {
		b.Fatalf("NewAttachPoint failed: %v", err)
	}
	root, err := a.Attach()
	if err != nil {
		b.Fatalf("Attach failed, err: %v", err)
	}
	defer root.Close()

	files := make([]p9.File, 0, 500)
	fds := make([]*fd.FD, 0, 500)
	uid := p9.UID(os.Getuid())
	gid := p9.GID(os.Getgid())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("same-%d", i)
		fd, file, _, _, err := root.Create(name, p9.ReadOnly, 0777, uid, gid)
		if err != nil {
			b.Fatalf("Create(%q): %v", name, err)
		}
		files = append(files, file)
		if fd != nil {
			fds = append(fds, fd)
		}

		// Avoid running out of FDs.
		if len(files) == cap(files) {
			b.StopTimer()
			for _, file := range files {
				file.Close()
			}
			files = files[:0]
			for _, fd := range fds {
				fd.Close()
			}
			fds = fds[:0]
			b.StartTimer()
		}
	}

	b.StopTimer()
	for _, file := range files {
		file.Close()
	}
	for _, fd := range fds {
		fd.Close()
	}
}

func BenchmarkCreateDiffOwner(b *testing.B) {
	if !specutils.HasCapabilities(capability.CAP_CHOWN) {
		b.Skipf("Test requires CAP_CHOWN")
	}

	path, _, err := setup(unix.S_IFDIR)
	if err != nil {
		b.Fatalf("%v", err)
	}
	defer os.RemoveAll(path)

	a, err := NewAttachPoint(path, Config{})
	if err != nil {
		b.Fatalf("NewAttachPoint failed: %v", err)
	}
	root, err := a.Attach()
	if err != nil {
		b.Fatalf("Attach failed, err: %v", err)
	}
	defer root.Close()

	files := make([]p9.File, 0, 500)
	fds := make([]*fd.FD, 0, 500)
	gid := p9.GID(os.Getgid())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		name := fmt.Sprintf("diff-%d", i)
		fd, file, _, _, err := root.Create(name, p9.ReadOnly, 0777, nobody, gid)
		if err != nil {
			b.Fatalf("Create(%q): %v", name, err)
		}
		files = append(files, file)
		if fd != nil {
			fds = append(fds, fd)
		}

		// Avoid running out of FDs.
		if len(files) == cap(files) {
			b.StopTimer()
			for _, file := range files {
				file.Close()
			}
			files = files[:0]
			for _, fd := range fds {
				fd.Close()
			}
			fds = fds[:0]
			b.StartTimer()
		}
	}

	b.StopTimer()
	for _, file := range files {
		file.Close()
	}
	for _, fd := range fds {
		fd.Close()
	}
}
