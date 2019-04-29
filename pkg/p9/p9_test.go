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
	"testing"
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

func TestFileModeToQID(t *testing.T) {
	for _, test := range []struct {
		// name identifies the test.
		name string

		// mode is the FileMode we start out with.
		mode FileMode

		// want is the corresponding QIDType we expect.
		want QIDType
	}{
		{
			name: "Directories are of type directory",
			mode: ModeDirectory,
			want: TypeDir,
		},
		{
			name: "Sockets are append-only files",
			mode: ModeSocket,
			want: TypeAppendOnly,
		},
		{
			name: "Named pipes are append-only files",
			mode: ModeNamedPipe,
			want: TypeAppendOnly,
		},
		{
			name: "Character devices are append-only files",
			mode: ModeCharacterDevice,
			want: TypeAppendOnly,
		},
		{
			name: "Symlinks are of type symlink",
			mode: ModeSymlink,
			want: TypeSymlink,
		},
		{
			name: "Regular files are of type regular",
			mode: ModeRegular,
			want: TypeRegular,
		},
		{
			name: "Block devices are regular files",
			mode: ModeBlockDevice,
			want: TypeRegular,
		},
	} {
		if qidType := test.mode.QIDType(); qidType != test.want {
			t.Errorf("ModeToQID test %s failed: got %o, wanted %o", test.name, qidType, test.want)
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
