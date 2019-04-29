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

package host

import (
	"io/ioutil"
	"os"
	"path"
	"syscall"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
)

// TestMultipleReaddir verifies that multiple Readdir calls return the same
// thing if they use different dir contexts.
func TestMultipleReaddir(t *testing.T) {
	p, err := ioutil.TempDir("", "readdir")
	if err != nil {
		t.Fatalf("Failed to create test dir: %v", err)
	}
	defer os.RemoveAll(p)

	f, err := os.Create(path.Join(p, "a.txt"))
	if err != nil {
		t.Fatalf("Failed to create a.txt: %v", err)
	}
	f.Close()

	f, err = os.Create(path.Join(p, "b.txt"))
	if err != nil {
		t.Fatalf("Failed to create b.txt: %v", err)
	}
	f.Close()

	fd, err := open(nil, p)
	if err != nil {
		t.Fatalf("Failed to open %q: %v", p, err)
	}
	ctx := contexttest.Context(t)
	n, err := newInode(ctx, newMountSource(ctx, p, fs.RootOwner, &Filesystem{}, fs.MountSourceFlags{}, false), fd, false, false)
	if err != nil {
		t.Fatalf("Failed to create inode: %v", err)
	}

	dirent := fs.NewDirent(n, "readdir")
	openFile, err := n.GetFile(ctx, dirent, fs.FileFlags{Read: true})
	if err != nil {
		t.Fatalf("Failed to get file: %v", err)
	}
	defer openFile.DecRef()

	c1 := &fs.DirCtx{DirCursor: new(string)}
	if _, err := openFile.FileOperations.(*fileOperations).IterateDir(ctx, c1, 0); err != nil {
		t.Fatalf("First Readdir failed: %v", err)
	}

	c2 := &fs.DirCtx{DirCursor: new(string)}
	if _, err := openFile.FileOperations.(*fileOperations).IterateDir(ctx, c2, 0); err != nil {
		t.Errorf("Second Readdir failed: %v", err)
	}

	if _, ok := c1.DentAttrs()["a.txt"]; !ok {
		t.Errorf("want a.txt in first Readdir, got %v", c1.DentAttrs())
	}
	if _, ok := c1.DentAttrs()["b.txt"]; !ok {
		t.Errorf("want b.txt in first Readdir, got %v", c1.DentAttrs())
	}

	if _, ok := c2.DentAttrs()["a.txt"]; !ok {
		t.Errorf("want a.txt in second Readdir, got %v", c2.DentAttrs())
	}
	if _, ok := c2.DentAttrs()["b.txt"]; !ok {
		t.Errorf("want b.txt in second Readdir, got %v", c2.DentAttrs())
	}
}

// TestCloseFD verifies fds will be closed.
func TestCloseFD(t *testing.T) {
	var p [2]int
	if err := syscall.Pipe(p[0:]); err != nil {
		t.Fatalf("Failed to create pipe %v", err)
	}
	defer syscall.Close(p[0])
	defer syscall.Close(p[1])

	// Use the write-end because we will detect if it's closed on the read end.
	ctx := contexttest.Context(t)
	file, err := NewFile(ctx, p[1], fs.RootOwner)
	if err != nil {
		t.Fatalf("Failed to create File: %v", err)
	}
	file.DecRef()

	s := make([]byte, 10)
	if c, err := syscall.Read(p[0], s); c != 0 || err != nil {
		t.Errorf("want 0, nil (EOF) from read end, got %v, %v", c, err)
	}
}
