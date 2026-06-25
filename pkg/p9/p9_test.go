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

package p9

import (
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFileModeHelpers(t *testing.T) {
	fns := map[FileMode]struct {
		// name identifies the file mode.
		name string

		// function is the function that should return true given the
		// right FileMode.
		function func(m FileMode) bool
	}{
		ModeRegular: {
			name:     "regular",
			function: FileMode.IsRegular,
		},
		ModeDirectory: {
			name:     "directory",
			function: FileMode.IsDir,
		},
		ModeNamedPipe: {
			name:     "named pipe",
			function: FileMode.IsNamedPipe,
		},
		ModeCharacterDevice: {
			name:     "character device",
			function: FileMode.IsCharacterDevice,
		},
		ModeBlockDevice: {
			name:     "block device",
			function: FileMode.IsBlockDevice,
		},
		ModeSymlink: {
			name:     "symlink",
			function: FileMode.IsSymlink,
		},
		ModeSocket: {
			name:     "socket",
			function: FileMode.IsSocket,
		},
	}
	for mode, info := range fns {
		// Make sure the mode doesn't identify as anything but itself.
		for testMode, testfns := range fns {
			if mode != testMode && testfns.function(mode) {
				t.Errorf("Mode %s returned true when asked if it was mode %s", info.name, testfns.name)
			}
		}

		// Make sure mode identifies as itself.
		if !info.function(mode) {
			t.Errorf("Mode %s returned false when asked if it was itself", info.name)
		}
	}
}

func TestP9ModeConverters(t *testing.T) {
	for _, m := range []FileMode{
		ModeRegular,
		ModeDirectory,
		ModeCharacterDevice,
		ModeBlockDevice,
		ModeSocket,
		ModeSymlink,
		ModeNamedPipe,
	} {
		if mb := ModeFromOS(m.OSMode()); mb != m {
			t.Errorf("Converting %o to OS.FileMode gives %o and is converted back as %o", m, m.OSMode(), mb)
		}
	}
}

func TestOSModeConverters(t *testing.T) {
	// Modes that can be converted back and forth.
	for _, m := range []os.FileMode{
		0, // Regular file.
		os.ModeDir,
		os.ModeCharDevice | os.ModeDevice,
		os.ModeDevice,
		os.ModeSocket,
		os.ModeSymlink,
		os.ModeNamedPipe,
	} {
		if mb := ModeFromOS(m).OSMode(); mb != m {
			t.Errorf("Converting %o to p9.FileMode gives %o and is converted back as %o", m, ModeFromOS(m), mb)
		}
	}

	// Modes that will be converted to a regular file since p9 cannot
	// express these.
	for _, m := range []os.FileMode{
		os.ModeAppend,
		os.ModeExclusive,
		os.ModeTemporary,
	} {
		if p9Mode := ModeFromOS(m); p9Mode != ModeRegular {
			t.Errorf("Converting %o to p9.FileMode should have given ModeRegular, but yielded %o", m, p9Mode)
		}
	}
}

func TestAttrMaskContains(t *testing.T) {
	req := AttrMask{Mode: true, Size: true}
	have := AttrMask{}
	if have.Contains(req) {
		t.Fatalf("AttrMask %v should not be a superset of %v", have, req)
	}
	have.Mode = true
	if have.Contains(req) {
		t.Fatalf("AttrMask %v should not be a superset of %v", have, req)
	}
	have.Size = true
	have.MTime = true
	if !have.Contains(req) {
		t.Fatalf("AttrMask %v should be a superset of %v", have, req)
	}
}

func TestStatToAttr(t *testing.T) {
	s := syscall.Stat_t{
		Mode:    0o644,
		Nlink:   2,
		Uid:     100,
		Gid:     200,
		Rdev:    10,
		Size:    1000,
		Blksize: 4096,
		Blocks:  8,
		Atim:    syscall.Timespec{Sec: 1, Nsec: 2},
		Mtim:    syscall.Timespec{Sec: 3, Nsec: 4},
		Ctim:    syscall.Timespec{Sec: 5, Nsec: 6},
	}

	req := AttrMaskAll()
	attr, mask := StatToAttr(&s, req)

	if attr.Mode != FileMode(s.Mode) {
		t.Errorf("attr.Mode = %v, want %v", attr.Mode, FileMode(s.Mode))
	}
	if attr.NLink != uint64(s.Nlink) {
		t.Errorf("attr.NLink = %v, want %v", attr.NLink, s.Nlink)
	}
	if attr.UID != UID(s.Uid) {
		t.Errorf("attr.UID = %v, want %v", attr.UID, s.Uid)
	}
	if attr.GID != GID(s.Gid) {
		t.Errorf("attr.GID = %v, want %v", attr.GID, s.Gid)
	}
	if attr.RDev != s.Rdev {
		t.Errorf("attr.RDev = %v, want %v", attr.RDev, s.Rdev)
	}
	if attr.Size != uint64(s.Size) {
		t.Errorf("attr.Size = %v, want %v", attr.Size, s.Size)
	}
	if attr.BlockSize != uint64(s.Blksize) {
		t.Errorf("attr.BlockSize = %v, want %v", attr.BlockSize, s.Blksize)
	}
	if attr.Blocks != uint64(s.Blocks) {
		t.Errorf("attr.Blocks = %v, want %v", attr.Blocks, s.Blocks)
	}
	if attr.ATimeSeconds != uint64(s.Atim.Sec) || attr.ATimeNanoSeconds != uint64(s.Atim.Nsec) {
		t.Errorf("attr.ATime = %v:%v, want %v:%v", attr.ATimeSeconds, attr.ATimeNanoSeconds, s.Atim.Sec, s.Atim.Nsec)
	}
	if attr.MTimeSeconds != uint64(s.Mtim.Sec) || attr.MTimeNanoSeconds != uint64(s.Mtim.Nsec) {
		t.Errorf("attr.MTime = %v:%v, want %v:%v", attr.MTimeSeconds, attr.MTimeNanoSeconds, s.Mtim.Sec, s.Mtim.Nsec)
	}
	if attr.CTimeSeconds != uint64(s.Ctim.Sec) || attr.CTimeNanoSeconds != uint64(s.Ctim.Nsec) {
		t.Errorf("attr.CTime = %v:%v, want %v:%v", attr.CTimeSeconds, attr.CTimeNanoSeconds, s.Ctim.Sec, s.Ctim.Nsec)
	}

	if mask.BTime || mask.Gen || mask.DataVersion {
		t.Errorf("mask still contains BTime, Gen or DataVersion: %v", mask)
	}

	// Test with unix.Stat_t
	u := unix.Stat_t{
		Mode:    0o755,
		Nlink:   3,
		Uid:     101,
		Gid:     201,
		Rdev:    11,
		Size:    2000,
		Blksize: 8192,
		Blocks:  16,
		Atim:    unix.Timespec{Sec: 10, Nsec: 20},
		Mtim:    unix.Timespec{Sec: 30, Nsec: 40},
		Ctim:    unix.Timespec{Sec: 50, Nsec: 60},
	}

	attr, _ = StatToAttr(&u, req)

	if attr.Mode != FileMode(u.Mode) {
		t.Errorf("attr.Mode = %v, want %v", attr.Mode, FileMode(u.Mode))
	}
	if attr.NLink != uint64(u.Nlink) {
		t.Errorf("attr.NLink = %v, want %v", attr.NLink, u.Nlink)
	}
	if attr.UID != UID(u.Uid) {
		t.Errorf("attr.UID = %v, want %v", attr.UID, u.Uid)
	}
	if attr.GID != GID(u.Gid) {
		t.Errorf("attr.GID = %v, want %v", attr.GID, u.Gid)
	}
	if attr.RDev != u.Rdev {
		t.Errorf("attr.RDev = %v, want %v", attr.RDev, u.Rdev)
	}
	if attr.Size != uint64(u.Size) {
		t.Errorf("attr.Size = %v, want %v", attr.Size, u.Size)
	}
	if attr.BlockSize != uint64(u.Blksize) {
		t.Errorf("attr.BlockSize = %v, want %v", attr.BlockSize, u.Blksize)
	}
	if attr.Blocks != uint64(u.Blocks) {
		t.Errorf("attr.Blocks = %v, want %v", attr.Blocks, u.Blocks)
	}
	if attr.ATimeSeconds != uint64(u.Atim.Sec) || attr.ATimeNanoSeconds != uint64(u.Atim.Nsec) {
		t.Errorf("attr.ATime = %v:%v, want %v:%v", attr.ATimeSeconds, attr.ATimeNanoSeconds, u.Atim.Sec, u.Atim.Nsec)
	}
}
