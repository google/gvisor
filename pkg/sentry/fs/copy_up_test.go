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

package fs_test

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/fs"
	_ "gvisor.dev/gvisor/pkg/sentry/fs/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

const (
	// origFileSize is the original file size. This many bytes should be
	// copied up before the test file is modified.
	origFileSize = 4096

	// truncatedFileSize is the size to truncate all test files.
	truncateFileSize = 10
)

// TestConcurrentCopyUp is a copy up stress test for an overlay.
//
// It creates a 64-level deep directory tree in the lower filesystem and
// populates the last subdirectory with 64 files containing random content:
//
//    /lower
//      /sudir0/.../subdir63/
//                     /file0
//                     ...
//                     /file63
//
// The files are truncated concurrently by 4 goroutines per file.
// These goroutines contend with copying up all parent 64 subdirectories
// as well as the final file content.
//
// At the end of the test, we assert that the files respect the new truncated
// size and contain the content we expect.
func TestConcurrentCopyUp(t *testing.T) {
	ctx := contexttest.Context(t)
	files := makeOverlayTestFiles(t)

	var wg sync.WaitGroup
	for _, file := range files {
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func(o *overlayTestFile) {
				if err := o.File.Dirent.Inode.Truncate(ctx, o.File.Dirent, truncateFileSize); err != nil {
					t.Fatalf("failed to copy up: %v", err)
				}
				wg.Done()
			}(file)
		}
	}
	wg.Wait()

	for _, file := range files {
		got := make([]byte, origFileSize)
		n, err := file.File.Readv(ctx, usermem.BytesIOSequence(got))
		if int(n) != truncateFileSize {
			t.Fatalf("read %d bytes from file, want %d", n, truncateFileSize)
		}
		if err != nil && err != io.EOF {
			t.Fatalf("read got error %v, want nil", err)
		}
		if !bytes.Equal(got[:n], file.content[:truncateFileSize]) {
			t.Fatalf("file content is %v, want %v", got[:n], file.content[:truncateFileSize])
		}
	}
}

type overlayTestFile struct {
	File    *fs.File
	name    string
	content []byte
}

func makeOverlayTestFiles(t *testing.T) []*overlayTestFile {
	ctx := contexttest.Context(t)

	// Create a lower tmpfs mount.
	fsys, _ := fs.FindFilesystem("tmpfs")
	lower, err := fsys.Mount(contexttest.Context(t), "", fs.MountSourceFlags{}, "", nil)
	if err != nil {
		t.Fatalf("failed to mount tmpfs: %v", err)
	}
	lowerRoot := fs.NewDirent(ctx, lower, "")

	// Make a deep set of subdirectories that everyone shares.
	next := lowerRoot
	for i := 0; i < 64; i++ {
		name := fmt.Sprintf("subdir%d", i)
		err := next.CreateDirectory(ctx, lowerRoot, name, fs.FilePermsFromMode(0777))
		if err != nil {
			t.Fatalf("failed to create dir %q: %v", name, err)
		}
		next, err = next.Walk(ctx, lowerRoot, name)
		if err != nil {
			t.Fatalf("failed to walk to %q: %v", name, err)
		}
	}

	// Make a bunch of files in the last directory.
	var files []*overlayTestFile
	for i := 0; i < 64; i++ {
		name := fmt.Sprintf("file%d", i)
		f, err := next.Create(ctx, next, name, fs.FileFlags{Read: true, Write: true}, fs.FilePermsFromMode(0666))
		if err != nil {
			t.Fatalf("failed to create file %q: %v", name, err)
		}
		defer f.DecRef()

		relname, _ := f.Dirent.FullName(lowerRoot)

		o := &overlayTestFile{
			name:    relname,
			content: make([]byte, origFileSize),
		}

		if _, err := rand.Read(o.content); err != nil {
			t.Fatalf("failed to read from /dev/urandom: %v", err)
		}

		if _, err := f.Writev(ctx, usermem.BytesIOSequence(o.content)); err != nil {
			t.Fatalf("failed to write content to file %q: %v", name, err)
		}

		files = append(files, o)
	}

	// Create an empty upper tmpfs mount which we will copy up into.
	upper, err := fsys.Mount(ctx, "", fs.MountSourceFlags{}, "", nil)
	if err != nil {
		t.Fatalf("failed to mount tmpfs: %v", err)
	}

	// Construct an overlay root.
	overlay, err := fs.NewOverlayRoot(ctx, upper, lower, fs.MountSourceFlags{})
	if err != nil {
		t.Fatalf("failed to construct overlay root: %v", err)
	}

	// Create a MountNamespace to traverse the file system.
	mns, err := fs.NewMountNamespace(ctx, overlay)
	if err != nil {
		t.Fatalf("failed to construct mount manager: %v", err)
	}

	// Walk to all of the files in the overlay, open them readable.
	for _, f := range files {
		maxTraversals := uint(0)
		d, err := mns.FindInode(ctx, mns.Root(), mns.Root(), f.name, &maxTraversals)
		if err != nil {
			t.Fatalf("failed to find %q: %v", f.name, err)
		}
		defer d.DecRef()

		f.File, err = d.Inode.GetFile(ctx, d, fs.FileFlags{Read: true})
		if err != nil {
			t.Fatalf("failed to open file %q readable: %v", f.name, err)
		}
	}

	return files
}
