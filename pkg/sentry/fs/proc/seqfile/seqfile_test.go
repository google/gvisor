// Copyright 2018 Google LLC
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

package seqfile

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs/ramfs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
)

type seqTest struct {
	actual []SeqData
	update bool
}

func (s *seqTest) Init() {
	var sq []SeqData
	// Create some SeqData.
	for i := 0; i < 10; i++ {
		var b []byte
		for j := 0; j < 10; j++ {
			b = append(b, byte(i))
		}
		sq = append(sq, SeqData{
			Buf:    b,
			Handle: &testHandle{i: i},
		})
	}
	s.actual = sq
}

// NeedsUpdate reports whether we need to update the data we've previously read.
func (s *seqTest) NeedsUpdate(int64) bool {
	return s.update
}

// ReadSeqFiledata returns a slice of SeqData which contains elements
// greater than the handle.
func (s *seqTest) ReadSeqFileData(ctx context.Context, handle SeqHandle) ([]SeqData, int64) {
	if handle == nil {
		return s.actual, 0
	}
	h := *handle.(*testHandle)
	var ret []SeqData
	for _, b := range s.actual {
		// We want the next one.
		h2 := *b.Handle.(*testHandle)
		if h2.i > h.i {
			ret = append(ret, b)
		}
	}
	return ret, 0
}

// Flatten a slice of slices into one slice.
func flatten(buf ...[]byte) []byte {
	var flat []byte
	for _, b := range buf {
		flat = append(flat, b...)
	}
	return flat
}

type testHandle struct {
	i int
}

type testTable struct {
	offset         int64
	readBufferSize int
	expectedData   []byte
	expectedError  error
}

func runTableTests(ctx context.Context, table []testTable, dirent *fs.Dirent) error {
	for _, tt := range table {
		file, err := dirent.Inode.InodeOperations.GetFile(ctx, dirent, fs.FileFlags{Read: true})
		if err != nil {
			return fmt.Errorf("GetFile returned error: %v", err)
		}

		data := make([]byte, tt.readBufferSize)
		resultLen, err := file.Preadv(ctx, usermem.BytesIOSequence(data), tt.offset)
		if err != tt.expectedError {
			return fmt.Errorf("t.Preadv(len: %v, offset: %v) (error) => %v expected %v", tt.readBufferSize, tt.offset, err, tt.expectedError)
		}
		expectedLen := int64(len(tt.expectedData))
		if resultLen != expectedLen {
			// We make this just an error so we wall through and print the data below.
			return fmt.Errorf("t.Preadv(len: %v, offset: %v) (size) => %v expected %v", tt.readBufferSize, tt.offset, resultLen, expectedLen)
		}
		if !bytes.Equal(data[:expectedLen], tt.expectedData) {
			return fmt.Errorf("t.Preadv(len: %v, offset: %v) (data) => %v expected %v", tt.readBufferSize, tt.offset, data[:expectedLen], tt.expectedData)
		}
	}
	return nil
}

func TestSeqFile(t *testing.T) {
	testSource := &seqTest{}
	testSource.Init()

	// Create a file that can be R/W.
	m := fs.NewPseudoMountSource()
	ctx := contexttest.Context(t)
	contents := map[string]*fs.Inode{
		"foo": NewSeqFileInode(ctx, testSource, m),
	}
	root := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0777))

	// How about opening it?
	inode := fs.NewInode(root, m, fs.StableAttr{Type: fs.Directory})
	dirent2, err := root.Lookup(ctx, inode, "foo")
	if err != nil {
		t.Fatalf("failed to walk to foo for n2: %v", err)
	}
	n2 := dirent2.Inode.InodeOperations
	file2, err := n2.GetFile(ctx, dirent2, fs.FileFlags{Read: true, Write: true})
	if err != nil {
		t.Fatalf("GetFile returned error: %v", err)
	}

	// Writing?
	if _, err := file2.Writev(ctx, usermem.BytesIOSequence([]byte("test"))); err == nil {
		t.Fatalf("managed to write to n2: %v", err)
	}

	// How about reading?
	dirent3, err := root.Lookup(ctx, inode, "foo")
	if err != nil {
		t.Fatalf("failed to walk to foo: %v", err)
	}
	n3 := dirent3.Inode.InodeOperations
	if n2 != n3 {
		t.Error("got n2 != n3, want same")
	}

	testSource.update = true

	table := []testTable{
		// Read past the end.
		{100, 4, []byte{}, io.EOF},
		{110, 4, []byte{}, io.EOF},
		{200, 4, []byte{}, io.EOF},
		// Read a truncated first line.
		{0, 4, testSource.actual[0].Buf[:4], nil},
		// Read the whole first line.
		{0, 10, testSource.actual[0].Buf, nil},
		// Read the whole first line + 5 bytes of second line.
		{0, 15, flatten(testSource.actual[0].Buf, testSource.actual[1].Buf[:5]), nil},
		// First 4 bytes of the second line.
		{10, 4, testSource.actual[1].Buf[:4], nil},
		// Read the two first lines.
		{0, 20, flatten(testSource.actual[0].Buf, testSource.actual[1].Buf), nil},
		// Read three lines.
		{0, 30, flatten(testSource.actual[0].Buf, testSource.actual[1].Buf, testSource.actual[2].Buf), nil},
		// Read everything, but use a bigger buffer than necessary.
		{0, 150, flatten(testSource.actual[0].Buf, testSource.actual[1].Buf, testSource.actual[2].Buf, testSource.actual[3].Buf, testSource.actual[4].Buf, testSource.actual[5].Buf, testSource.actual[6].Buf, testSource.actual[7].Buf, testSource.actual[8].Buf, testSource.actual[9].Buf), nil},
		// Read the last 3 bytes.
		{97, 10, testSource.actual[9].Buf[7:], nil},
	}
	if err := runTableTests(ctx, table, dirent2); err != nil {
		t.Errorf("runTableTest failed with testSource.update = %v : %v", testSource.update, err)
	}

	// Disable updates and do it again.
	testSource.update = false
	if err := runTableTests(ctx, table, dirent2); err != nil {
		t.Errorf("runTableTest failed with testSource.update = %v: %v", testSource.update, err)
	}
}

// Test that we behave correctly when the file is updated.
func TestSeqFileFileUpdated(t *testing.T) {
	testSource := &seqTest{}
	testSource.Init()
	testSource.update = true

	// Create a file that can be R/W.
	m := fs.NewPseudoMountSource()
	ctx := contexttest.Context(t)
	contents := map[string]*fs.Inode{
		"foo": NewSeqFileInode(ctx, testSource, m),
	}
	root := ramfs.NewDir(ctx, contents, fs.RootOwner, fs.FilePermsFromMode(0777))

	// How about opening it?
	inode := fs.NewInode(root, m, fs.StableAttr{Type: fs.Directory})
	dirent2, err := root.Lookup(ctx, inode, "foo")
	if err != nil {
		t.Fatalf("failed to walk to foo for dirent2: %v", err)
	}

	table := []testTable{
		{0, 16, flatten(testSource.actual[0].Buf, testSource.actual[1].Buf[:6]), nil},
	}
	if err := runTableTests(ctx, table, dirent2); err != nil {
		t.Errorf("runTableTest failed: %v", err)
	}
	// Delete the first entry.
	cut := testSource.actual[0].Buf
	testSource.actual = testSource.actual[1:]

	table = []testTable{
		// Try reading buffer 0 with an offset. This will not delete the old data.
		{1, 5, cut[1:6], nil},
		// Reset our file by reading at offset 0.
		{0, 10, testSource.actual[0].Buf, nil},
		{16, 14, flatten(testSource.actual[1].Buf[6:], testSource.actual[2].Buf), nil},
		// Read the same data a second time.
		{16, 14, flatten(testSource.actual[1].Buf[6:], testSource.actual[2].Buf), nil},
		// Read the following two lines.
		{30, 20, flatten(testSource.actual[3].Buf, testSource.actual[4].Buf), nil},
	}
	if err := runTableTests(ctx, table, dirent2); err != nil {
		t.Errorf("runTableTest failed after removing first entry: %v", err)
	}

	// Add a new duplicate line in the middle (6666...)
	after := testSource.actual[5:]
	testSource.actual = testSource.actual[:4]
	// Note the list must be sorted.
	testSource.actual = append(testSource.actual, after[0])
	testSource.actual = append(testSource.actual, after...)

	table = []testTable{
		{50, 20, flatten(testSource.actual[4].Buf, testSource.actual[5].Buf), nil},
	}
	if err := runTableTests(ctx, table, dirent2); err != nil {
		t.Errorf("runTableTest failed after adding middle entry: %v", err)
	}
	// This will be used in a later test.
	oldTestData := testSource.actual

	// Delete everything.
	testSource.actual = testSource.actual[:0]
	table = []testTable{
		{20, 20, []byte{}, io.EOF},
	}
	if err := runTableTests(ctx, table, dirent2); err != nil {
		t.Errorf("runTableTest failed after removing all entries: %v", err)
	}
	// Restore some of the data.
	testSource.actual = oldTestData[:1]
	table = []testTable{
		{6, 20, testSource.actual[0].Buf[6:], nil},
	}
	if err := runTableTests(ctx, table, dirent2); err != nil {
		t.Errorf("runTableTest failed after adding first entry back: %v", err)
	}

	// Re-extend the data
	testSource.actual = oldTestData
	table = []testTable{
		{30, 20, flatten(testSource.actual[3].Buf, testSource.actual[4].Buf), nil},
	}
	if err := runTableTests(ctx, table, dirent2); err != nil {
		t.Errorf("runTableTest failed after extending testSource: %v", err)
	}
}
