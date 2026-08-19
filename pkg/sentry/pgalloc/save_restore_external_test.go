// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pgalloc

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

func newTestMemoryFile(t *testing.T, path string, adopt bool) *MemoryFile {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatalf("opening %q: %v", path, err)
	}
	mf, err := NewMemoryFile(f, MemoryFileOpts{
		DelayedEviction:         DelayedEvictionManual,
		DisableIMAWorkAround:    true,
		DisableMemoryAccounting: true,
		DecommitOnDestroy:       false,
		AdoptExistingFile:       adopt,
	})
	if err != nil {
		t.Fatalf("NewMemoryFile(%q): %v", path, err)
	}
	return mf
}

func writeTestRange(t *testing.T, mf *MemoryFile, fr memmap.FileRange, fill byte) {
	t.Helper()
	bs, err := mf.MapInternal(fr, hostarch.ReadWrite)
	if err != nil {
		t.Fatalf("MapInternal(%v): %v", fr, err)
	}
	for !bs.IsEmpty() {
		s := bs.Head().ToSlice()
		for i := range s {
			s[i] = fill
		}
		bs = bs.Tail()
	}
}

func readTestRange(t *testing.T, mf *MemoryFile, fr memmap.FileRange) []byte {
	t.Helper()
	bs, err := mf.MapInternal(fr, hostarch.Read)
	if err != nil {
		t.Fatalf("MapInternal(%v): %v", fr, err)
	}
	var out []byte
	for !bs.IsEmpty() {
		out = append(out, bs.Head().ToSlice()...)
		bs = bs.Tail()
	}
	if uint64(len(out)) != fr.Length() {
		t.Fatalf("read %d bytes, want %d", len(out), fr.Length())
	}
	return out
}

// TestExternalContentRoundtrip verifies that a MemoryFile saved with
// SaveOpts.ExternalContent only emits segment metadata, and that the metadata
// can be restored over the SAME host file with AdoptExistingFile without any
// page contents being serialized.
func TestExternalContentRoundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "filestore")

	// Build an original MemoryFile with two allocated segments with distinct
	// contents and a hole in between.
	orig := newTestMemoryFile(t, path, false)
	fr1, err := orig.Allocate(2*hostarch.PageSize, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	writeTestRange(t, orig, fr1, 0xab)
	fr2, err := orig.Allocate(hostarch.PageSize, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	writeTestRange(t, orig, fr2, 0xcd)

	// Save metadata-only.
	var buf bytes.Buffer
	saveOpts := &SaveOpts{ExternalContent: true}
	if err := orig.SaveTo(context.Background(), &buf, saveOpts); err != nil {
		t.Fatalf("SaveTo(ExternalContent): %v", err)
	}
	// The saved image must be tiny compared to the allocated data
	// (segment tables only, no pages).
	if maxMeta := 64 << 10; buf.Len() > maxMeta {
		t.Errorf("metadata-only save emitted %d bytes, want <= %d", buf.Len(), maxMeta)
	}
	metadataImage := buf.Bytes()

	// The host file must not have been truncated to zero by adoption.
	if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
		t.Fatalf("host file after save: size=%d err=%v (contents must be preserved)", fi.Size(), err)
	}

	// Restore over the same host file with AdoptExistingFile.
	adopted := newTestMemoryFile(t, path, true)
	if fi, err := os.Stat(path); err != nil || fi.Size() == 0 {
		t.Fatalf("host file truncated by NewMemoryFile(AdoptExistingFile): size=%d err=%v", fi.Size(), err)
	}
	if err := adopted.LoadFrom(context.Background(), bytes.NewReader(metadataImage), &LoadOpts{}); err != nil {
		t.Fatalf("LoadFrom(ContentExternal): %v", err)
	}

	// Contents must be identical, served from the adopted file itself.
	got1 := readTestRange(t, adopted, fr1)
	for i, b := range got1 {
		if b != 0xab {
			t.Fatalf("fr1 byte %d = %#x, want 0xab", i, b)
		}
	}
	got2 := readTestRange(t, adopted, fr2)
	for i, b := range got2 {
		if b != 0xcd {
			t.Fatalf("fr2 byte %d = %#x, want 0xcd", i, b)
		}
	}
}

// TestExternalContentRequiresAdoption verifies that ContentExternal metadata
// is rejected when the backing file was not adopted (i.e. was truncated empty
// at creation), which would otherwise silently restore zero pages.
func TestExternalContentRequiresAdoption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "filestore")

	orig := newTestMemoryFile(t, path, false)
	fr, err := orig.Allocate(hostarch.PageSize, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	writeTestRange(t, orig, fr, 0x11)

	var buf bytes.Buffer
	if err := orig.SaveTo(context.Background(), &buf, &SaveOpts{ExternalContent: true}); err != nil {
		t.Fatalf("SaveTo(ExternalContent): %v", err)
	}
	metadataImage := buf.Bytes()

	// A fresh (non-adopted) MemoryFile is created empty; loading
	// ContentExternal metadata into it must fail loudly.
	fresh := newTestMemoryFile(t, filepath.Join(dir, "fresh"), false)
	if err := fresh.LoadFrom(context.Background(), bytes.NewReader(metadataImage), &LoadOpts{}); err == nil {
		t.Fatal("LoadFrom(ContentExternal) on non-adopted empty file unexpectedly succeeded")
	}
}

// TestExternalContentRejectsUndersizedAdoption verifies that adopting a file
// smaller than the saved chunk table requires fails instead of silently
// restoring holes.
func TestExternalContentRejectsUndersizedAdoption(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "filestore")

	orig := newTestMemoryFile(t, path, false)
	fr, err := orig.Allocate(hostarch.PageSize, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	writeTestRange(t, orig, fr, 0x22)

	var buf bytes.Buffer
	if err := orig.SaveTo(context.Background(), &buf, &SaveOpts{ExternalContent: true}); err != nil {
		t.Fatalf("SaveTo(ExternalContent): %v", err)
	}
	metadataImage := buf.Bytes()

	// Shrink the host file below the chunk-table requirement.
	if err := os.Truncate(path, hostarch.PageSize); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	adopted := newTestMemoryFile(t, path, true)
	if err := adopted.LoadFrom(context.Background(), bytes.NewReader(metadataImage), &LoadOpts{}); err == nil {
		t.Fatal("LoadFrom(ContentExternal) with undersized adopted file unexpectedly succeeded")
	}
}

// newTestMemoryFileDecommit is newTestMemoryFile with a DecommitOnDestroy
// override, mimicking runsc's createPrivateMemoryFile (upstream default:
// DecommitOnDestroy true for disk-backed private memory files).
func newTestMemoryFileDecommit(t *testing.T, path string, decommit bool) *MemoryFile {
	t.Helper()
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatalf("opening %q: %v", path, err)
	}
	mf, err := NewMemoryFile(f, MemoryFileOpts{
		DelayedEviction:         DelayedEvictionManual,
		DisableIMAWorkAround:    true,
		DisableMemoryAccounting: true,
		DecommitOnDestroy:       decommit,
	})
	if err != nil {
		t.Fatalf("NewMemoryFile(%q): %v", path, err)
	}
	return mf
}

func hostFilePatternOk(t *testing.T, path string, fill byte, length uint64) bool {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading host file %q: %v", path, err)
	}
	if uint64(len(got)) < length {
		t.Fatalf("host file %q is %d bytes, want >= %d", path, len(got), length)
	}
	for i := uint64(0); i < length; i++ {
		if got[i] != fill {
			return false
		}
	}
	return true
}

// TestExternalContentSurvivesDestroy verifies the fd-hold invariant: after
// SaveTo(ExternalContent), destroying the MemoryFile must NOT decommit the
// backing host file — an external fd holder or snapshot references the same
// inode, and the checkpoint is useless without the file's contents.
func TestExternalContentSurvivesDestroy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filestore")
	const size = 1 << 20
	const fill = 0x5a

	mf := newTestMemoryFileDecommit(t, path, true /* decommit */)
	fr, err := mf.Allocate(size, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	writeTestRange(t, mf, fr, fill)
	if err := mf.SaveTo(context.Background(), &bytes.Buffer{}, &SaveOpts{ExternalContent: true}); err != nil {
		t.Fatalf("SaveTo(ExternalContent): %v", err)
	}
	mf.Destroy()

	// Destroy is asynchronous (releaser goroutine). Poll: the contents must
	// remain intact; the pre-fix behavior would punch holes (read as zeros).
	deadline := time.Now().Add(5 * time.Second)
	for {
		if !hostFilePatternOk(t, path, fill, size) {
			t.Fatalf("host file contents were destroyed despite ExternalContent save (decommitted on destroy)")
		}
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// TestDefaultSaveStillDecommitsOnDestroy is the control for the above: the
// default save path does not arm contentExternal, so DecommitOnDestroy must
// still release the host file's disk space.
func TestDefaultSaveStillDecommitsOnDestroy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filestore")
	const size = 1 << 20
	const fill = 0xa5

	mf := newTestMemoryFileDecommit(t, path, true /* decommit */)
	fr, err := mf.Allocate(size, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	writeTestRange(t, mf, fr, fill)
	if err := mf.SaveTo(context.Background(), &bytes.Buffer{}, &SaveOpts{}); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	mf.Destroy()

	// Poll until the releaser decommits (contents become holes/zeros).
	deadline := time.Now().Add(5 * time.Second)
	for {
		if !hostFilePatternOk(t, path, fill, size) {
			return // decommitted as expected
		}
		if time.Now().After(deadline) {
			t.Fatalf("host file contents survived Destroy after a default (non-external) save; DecommitOnDestroy regression")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
