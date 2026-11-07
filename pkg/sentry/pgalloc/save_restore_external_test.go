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
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	pgallocpb "gvisor.dev/gvisor/pkg/sentry/pgalloc/pgalloc_metadata_go_proto"
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
	saveOpts := &SaveOpts{ExternalContent: true, ExitAfterSaving: true}
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

func TestExternalContentEmptyRoundtrip(t *testing.T) {
	for _, grow := range []bool{false, true} {
		name := "empty"
		if grow {
			name = "unexpected_contents"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "filestore")
			orig := newTestMemoryFile(t, path, false)
			defer orig.Destroy()
			var buf bytes.Buffer
			if err := orig.SaveTo(context.Background(), &buf, &SaveOpts{ExternalContent: true, ExitAfterSaving: true}); err != nil {
				t.Fatal(err)
			}
			if grow {
				if err := os.WriteFile(path, []byte("unexpected contents"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			adopted := newTestMemoryFile(t, path, true)
			defer adopted.Destroy()
			err := adopted.LoadFrom(context.Background(), &buf, &LoadOpts{})
			if grow {
				if err == nil || !strings.Contains(err.Error(), "file size") {
					t.Fatalf("LoadFrom: got %v, want size mismatch", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := adopted.ChunkCount(); got != 0 {
				t.Fatalf("restored chunk count = %d, want 0", got)
			}
			// The restored empty layer must remain usable for new writes.
			fr, err := adopted.Allocate(hostarch.PageSize, AllocOpts{Kind: usage.Anonymous})
			if err != nil {
				t.Fatal(err)
			}
			writeTestRange(t, adopted, fr, 0x5a)
			if got := readTestRange(t, adopted, fr); !bytes.Equal(got, bytes.Repeat([]byte{0x5a}, int(hostarch.PageSize))) {
				t.Fatal("write to restored empty layer did not persist")
			}
		})
	}
}

func TestExternalContentRejectsShortFingerprint(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filestore")
	orig := newTestMemoryFile(t, path, false)
	defer orig.Destroy()
	// Emulate malformed snapshot credentials in serialized metadata.
	orig.mu.Lock()
	orig.externalSavedFingerprint = "x"
	orig.mu.Unlock()
	var buf bytes.Buffer
	if err := orig.SaveTo(context.Background(), &buf, &SaveOpts{ExternalContent: true, ExitAfterSaving: true}); err != nil {
		t.Fatal(err)
	}
	adopted := newTestMemoryFile(t, path, true)
	defer adopted.Destroy()
	if err := adopted.LoadFrom(context.Background(), &buf, &LoadOpts{}); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("LoadFrom: got %v, want fingerprint mismatch", err)
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
	if err := orig.SaveTo(context.Background(), &buf, &SaveOpts{ExternalContent: true, ExitAfterSaving: true}); err != nil {
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
	if err := orig.SaveTo(context.Background(), &buf, &SaveOpts{ExternalContent: true, ExitAfterSaving: true}); err != nil {
		t.Fatalf("SaveTo(ExternalContent): %v", err)
	}
	metadataImage := buf.Bytes()

	// Both an undersized file and an empty file must be rejected when
	// the saved chunk table describes a nonempty writable layer.
	for _, size := range []int64{hostarch.PageSize, 0} {
		if err := os.Truncate(path, size); err != nil {
			t.Fatalf("truncate: %v", err)
		}
		adopted := newTestMemoryFile(t, path, true)
		if err := adopted.LoadFrom(context.Background(), bytes.NewReader(metadataImage), &LoadOpts{}); err == nil {
			t.Fatalf("LoadFrom(ContentExternal) with file size %d unexpectedly succeeded", size)
		}
	}
}

// TestExternalContentRejectsSizeMismatch verifies that adopting a file whose
// size differs from the checkpointed filestore size fails exactly (a larger
// artifact is no longer accepted either).
func TestExternalContentRejectsSizeMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "filestore")

	orig := newTestMemoryFile(t, path, false)
	fr, err := orig.Allocate(hostarch.PageSize, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	writeTestRange(t, orig, fr, 0x33)

	var buf bytes.Buffer
	if err := orig.SaveTo(context.Background(), &buf, &SaveOpts{ExternalContent: true, ExitAfterSaving: true}); err != nil {
		t.Fatalf("SaveTo(ExternalContent): %v", err)
	}
	metadataImage := buf.Bytes()

	// Grow the host file beyond the saved size: large enough per the legacy
	// lower-bound check, but not the exact recorded size.
	if err := os.Truncate(path, 4*hostarch.PageSize); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	adopted := newTestMemoryFile(t, path, true)
	if err := adopted.LoadFrom(context.Background(), bytes.NewReader(metadataImage), &LoadOpts{}); err == nil {
		t.Fatal("LoadFrom(ContentExternal) with oversized adopted file unexpectedly succeeded")
	}
}

// TestExternalContentRejectsDivergedContents verifies the sampled
// fingerprint: an adopted file with the SAME size but DIFFERENT contents
// (e.g. the original filestore kept running after a leave-running
// checkpoint) must be rejected instead of silently restoring foreign data.
func TestExternalContentRejectsDivergedContents(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "filestore")

	orig := newTestMemoryFile(t, path, false)
	// Ensure the file is larger than the 4KiB fingerprint sampling chunk so
	// the mutation lands inside a sampled region (first chunk).
	const nPages = 3
	for i := 0; i < nPages; i++ {
		fr, err := orig.Allocate(hostarch.PageSize, AllocOpts{Kind: usage.Anonymous})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		writeTestRange(t, orig, fr, 0x44)
	}

	var buf bytes.Buffer
	if err := orig.SaveTo(context.Background(), &buf, &SaveOpts{ExternalContent: true, ExitAfterSaving: true}); err != nil {
		t.Fatalf("SaveTo(ExternalContent): %v", err)
	}
	metadataImage := buf.Bytes()

	// Diverge the contents at the same size (post-leave-running divergence).
	func() {
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			t.Fatalf("open for mutation: %v", err)
		}
		defer f.Close()
		mutation := make([]byte, hostarch.PageSize)
		for i := range mutation {
			mutation[i] = 0x99
		}
		if _, err := f.WriteAt(mutation, 0); err != nil {
			t.Fatalf("WriteAt: %v", err)
		}
	}()

	adopted := newTestMemoryFile(t, path, true)
	if err := adopted.LoadFrom(context.Background(), bytes.NewReader(metadataImage), &LoadOpts{}); err == nil {
		t.Fatal("LoadFrom(ContentExternal) with diverged same-size contents unexpectedly succeeded")
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
// backing host file - an external fd holder or snapshot references the same
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
	if err := mf.SaveTo(context.Background(), &bytes.Buffer{}, &SaveOpts{ExternalContent: true, ExitAfterSaving: true}); err != nil {
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

// TestExternalContentSnapshotCredentialsResetPerSaveWindow verifies that the
// snapshot credentials stashed by SnapshotToFd() during one save window do
// not leak into a subsequent window's ExternalContent metadata. Simulates a
// --filestore-snapshot-dir checkpoint followed (on the same live MemoryFile)
// by a plain --skip-filestore-pages checkpoint after the original diverged:
// the second save must describe the backing file's current contents.
func TestExternalContentSnapshotCredentialsResetPerSaveWindow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "filestore")
	stalePath := filepath.Join(dir, "filestore-stale-snapshot")

	orig := newTestMemoryFile(t, path, false)
	const nPages = 3
	for i := 0; i < nPages; i++ {
		fr, err := orig.Allocate(hostarch.PageSize, AllocOpts{Kind: usage.Anonymous})
		if err != nil {
			t.Fatalf("Allocate: %v", err)
		}
		writeTestRange(t, orig, fr, 0x44)
	}

	// The "stale snapshot artifact": same size, different contents in the
	// fingerprint-sampled region (what the file looked like at window 1).
	staleData := make([]byte, nPages*hostarch.PageSize)
	for i := range staleData {
		staleData[i] = 0x77
	}
	if err := os.WriteFile(stalePath, staleData, 0600); err != nil {
		t.Fatalf("WriteFile(stale): %v", err)
	}

	// Emulate the state left behind by a completed window-1 SnapshotToFd()
	// (FICLONE is not available on all test filesystems, so stash the
	// credentials the snapshot would have recorded directly).
	func() {
		sf, err := os.Open(stalePath)
		if err != nil {
			t.Fatalf("open stale: %v", err)
		}
		defer sf.Close()
		fp, err := checkpoint.FingerprintFile(sf)
		if err != nil {
			t.Fatalf("checkpoint.FingerprintFile(stale): %v", err)
		}
		fi, err := sf.Stat()
		if err != nil {
			t.Fatalf("stat stale: %v", err)
		}
		orig.mu.Lock()
		defer orig.mu.Unlock()
		orig.externalSavedSize = uint64(fi.Size())
		orig.externalSavedFingerprint = fp
	}()

	// Window 2 (plain ExternalContent save): BeginSaveWindow must discard
	// the stale credentials so the metadata describes the current file.
	orig.BeginSaveWindow()
	var buf bytes.Buffer
	if err := orig.SaveTo(context.Background(), &buf, &SaveOpts{ExternalContent: true, ExitAfterSaving: true}); err != nil {
		t.Fatalf("SaveTo(ExternalContent): %v", err)
	}
	metadataImage := buf.Bytes()

	// Adopting the CURRENT backing file must succeed; without the reset it
	// would be rejected against the stale window-1 fingerprint.
	adopted := newTestMemoryFile(t, path, true)
	if err := adopted.LoadFrom(context.Background(), bytes.NewReader(metadataImage), &LoadOpts{}); err != nil {
		t.Fatalf("LoadFrom(ContentExternal) against current file failed (stale window-1 credentials leaked): %v", err)
	}

	// Adopting the stale snapshot artifact for window-2 metadata must fail:
	// it no longer describes the backing file's contents.
	staleAdopted := newTestMemoryFile(t, stalePath, true)
	if err := staleAdopted.LoadFrom(context.Background(), bytes.NewReader(metadataImage), &LoadOpts{}); err == nil {
		t.Fatal("LoadFrom(ContentExternal) against stale snapshot artifact unexpectedly succeeded")
	}
}

func TestOrdinaryCheckpointRejectsAdoptedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "filestore")
	orig := newTestMemoryFile(t, path, false)
	defer orig.Destroy()
	var image bytes.Buffer
	if err := orig.SaveTo(context.Background(), &image, &SaveOpts{}); err != nil {
		t.Fatal(err)
	}
	const contents = "existing artifact must remain intact"
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
	adopted := newTestMemoryFile(t, path, true)
	defer adopted.Destroy()
	if err := adopted.LoadFrom(context.Background(), &image, &LoadOpts{}); err == nil {
		t.Fatal("ordinary checkpoint accepted an adopted backing file")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != contents {
		t.Fatalf("rejected load modified artifact: %q", got)
	}
}

func destroyTestMemoryFile(t *testing.T, mf *MemoryFile) {
	t.Helper()
	mf.Destroy()
	deadline := time.Now().Add(5 * time.Second)
	for {
		mf.mu.Lock()
		closed := mf.file == nil
		mf.mu.Unlock()
		if closed {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("MemoryFile destruction did not complete")
		}
		time.Sleep(time.Millisecond)
	}
}

func legacyExternalImage(t *testing.T, image []byte) []byte {
	t.Helper()
	length := binary.LittleEndian.Uint64(image[:8])
	var pb pgallocpb.MemoryFileMetadataProto
	if err := proto.Unmarshal(image[8:8+length], &pb); err != nil {
		t.Fatal(err)
	}
	pb.ContentExternalFileSize = 0
	pb.ContentExternalFingerprint = ""
	data, err := proto.Marshal(&pb)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]byte, 8, 8+len(data))
	binary.LittleEndian.PutUint64(out, uint64(len(data)))
	return append(out, data...)
}

// TestAdoptedLoadFailurePreservesFile exercises the destroy-on-load-error
// sequence for disk-backed private MemoryFiles, including partial loads whose
// chunk metadata has been imported but whose mappings have not been created.
func TestAdoptedLoadFailurePreservesFile(t *testing.T) {
	source := newTestMemoryFile(t, filepath.Join(t.TempDir(), "source"), false)
	defer source.Destroy()
	fr, err := source.Allocate(hostarch.PageSize, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatal(err)
	}
	writeTestRange(t, source, fr, 0x5a)
	var ordinary, external bytes.Buffer
	if err := source.SaveTo(context.Background(), &ordinary, &SaveOpts{}); err != nil {
		t.Fatal(err)
	}
	if err := source.SaveTo(context.Background(), &external, &SaveOpts{ExternalContent: true, ExitAfterSaving: true}); err != nil {
		t.Fatal(err)
	}
	info, err := source.file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		image    []byte
		size     int64
		fill     byte
		readOnly bool
		wantErr  string
	}{
		{"ordinary", ordinary.Bytes(), int64(hostarch.PageSize), 0xa5, false, "ordinary checkpoint"},
		{"truncated_metadata", external.Bytes()[:8], info.Size(), 0x5a, false, "read metadata"},
		{"undersized", external.Bytes(), int64(hostarch.PageSize), 0x5a, false, "smaller than required"},
		{"oversized", external.Bytes(), info.Size() + int64(hostarch.PageSize), 0x5a, false, "checkpointed filestore size"},
		{"diverged", external.Bytes(), info.Size(), 0xa5, false, "fingerprint mismatch"},
		{"mmap_failure", external.Bytes(), info.Size(), 0x5a, true, "failed to mmap"},
		{"legacy_mmap_failure", legacyExternalImage(t, external.Bytes()), info.Size() + int64(hostarch.PageSize), 0x5a, true, "failed to mmap"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "artifact")
			file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			if err := file.Truncate(tc.size); err != nil {
				t.Fatal(err)
			}
			contents := bytes.Repeat([]byte{tc.fill}, int(hostarch.PageSize))
			if _, err := file.WriteAt(contents, int64(fr.Start)); err != nil {
				t.Fatal(err)
			}
			flags := os.O_RDWR
			if tc.readOnly {
				flags = os.O_RDONLY
			}
			input, err := os.OpenFile(path, flags, 0)
			if err != nil {
				t.Fatal(err)
			}
			mf, err := NewMemoryFile(input, MemoryFileOpts{
				AdoptExistingFile:       true,
				DiskBackedFile:          true,
				DecommitOnDestroy:       true,
				DelayedEviction:         DelayedEvictionManual,
				DisableIMAWorkAround:    true,
				DisableMemoryAccounting: true,
			})
			if err != nil {
				input.Close()
				t.Fatal(err)
			}
			var loadErr error
			// Cleanup may start from DoneCallback, before LoadFrom returns.
			err = mf.LoadFrom(context.Background(), bytes.NewReader(tc.image), &LoadOpts{
				DoneCallback: func(err error) {
					loadErr = err
					destroyTestMemoryFile(t, mf)
				},
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) || loadErr != err {
				t.Fatalf("LoadFrom = %v, callback = %v; want %q", err, loadErr, tc.wantErr)
			}
			if _, err := input.Stat(); err == nil {
				t.Fatal("failed load followed by Destroy left the adopted FD open")
			}
			got := make([]byte, len(contents))
			if _, err := file.ReadAt(got, int64(fr.Start)); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, contents) {
				t.Fatal("failed load followed by Destroy changed the adopted file")
			}
			if got, err := file.Stat(); err != nil || got.Size() != tc.size {
				t.Fatalf("file size changed after failed load and Destroy: stat=%v, err=%v", got, err)
			}
		})
	}
}

func TestSuccessfulAdoptionDecommitsOnDestroy(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	source := newTestMemoryFile(t, path, false)
	fr, err := source.Allocate(hostarch.PageSize, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatal(err)
	}
	writeTestRange(t, source, fr, 0x5a)
	var image bytes.Buffer
	if err := source.SaveTo(context.Background(), &image, &SaveOpts{ExternalContent: true, ExitAfterSaving: true}); err != nil {
		t.Fatal(err)
	}
	destroyTestMemoryFile(t, source)
	adopted := newTestMemoryFile(t, path, true)
	adopted.opts.DiskBackedFile = true
	adopted.opts.DecommitOnDestroy = true
	if err := adopted.LoadFrom(context.Background(), &image, &LoadOpts{}); err != nil {
		destroyTestMemoryFile(t, adopted)
		t.Fatal(err)
	}
	destroyTestMemoryFile(t, adopted)
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	got := make([]byte, hostarch.PageSize)
	if _, err := file.ReadAt(got, int64(fr.Start)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, make([]byte, len(got))) {
		t.Fatal("successful adoption no longer decommits on destruction")
	}
}

func TestLegacyExternalAdoptionDropsTail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	source := newTestMemoryFile(t, path, false)
	fr, err := source.Allocate(hostarch.PageSize, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatal(err)
	}
	writeTestRange(t, source, fr, 0x5a)
	var image bytes.Buffer
	if err := source.SaveTo(context.Background(), &image, &SaveOpts{ExternalContent: true, ExitAfterSaving: true}); err != nil {
		t.Fatal(err)
	}
	destroyTestMemoryFile(t, source)
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.WriteAt(bytes.Repeat([]byte{0xa5}, int(hostarch.PageSize)), chunkSize); err != nil {
		t.Fatal(err)
	}
	adopted := newTestMemoryFile(t, path, true)
	defer adopted.Destroy()
	if err := adopted.LoadFrom(context.Background(), bytes.NewReader(legacyExternalImage(t, image.Bytes())), &LoadOpts{}); err != nil {
		t.Fatal(err)
	}
	if got := readTestRange(t, adopted, fr); !bytes.Equal(got, bytes.Repeat([]byte{0x5a}, int(fr.Length()))) {
		t.Fatal("legacy adoption changed saved contents")
	}
	newRange, err := adopted.Allocate(chunkSize, AllocOpts{Kind: usage.Anonymous})
	if err != nil {
		t.Fatal(err)
	}
	if newRange.Start > chunkSize || newRange.End < chunkSize+hostarch.PageSize {
		t.Fatalf("new allocation %v does not cover the old artifact tail", newRange)
	}
	got := readTestRange(t, adopted, memmap.FileRange{Start: chunkSize, End: chunkSize + hostarch.PageSize})
	if !bytes.Equal(got, make([]byte, len(got))) {
		t.Fatal("growing restored legacy MemoryFile exposed the old artifact tail")
	}
}

func TestExternalContentPreservationLifetime(t *testing.T) {
	for _, resume := range []bool{false, true} {
		for _, snapshot := range []bool{false, true} {
			t.Run(fmt.Sprintf("resume=%t/snapshot=%t", resume, snapshot), func(t *testing.T) {
				mf := newTestMemoryFile(t, filepath.Join(t.TempDir(), "filestore"), false)
				defer mf.Destroy()
				if snapshot {
					mf.mu.Lock()
					mf.externalSavedFingerprint = "snapshot"
					mf.mu.Unlock()
				}
				if err := mf.SaveTo(context.Background(), &bytes.Buffer{}, &SaveOpts{ExternalContent: true, ExitAfterSaving: !resume}); err != nil {
					t.Fatal(err)
				}
				mf.mu.Lock()
				got := mf.contentExternal
				mf.mu.Unlock()
				if want := !resume && !snapshot; got != want {
					t.Fatalf("preserve backing file = %t, want %t", got, want)
				}
				mf.BeginSaveWindow()
				mf.mu.Lock()
				got = mf.contentExternal
				mf.mu.Unlock()
				if got {
					t.Fatal("preservation leaked into next save window")
				}
			})
		}
	}
}

func TestFilestoreSnapshotWaitsForWaste(t *testing.T) {
	source, err := os.CreateTemp(t.TempDir(), "source")
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	// No releaser goroutine: the test controls when waste becomes quiescent.
	mf := &MemoryFile{file: source}
	dst, err := os.CreateTemp(t.TempDir(), "snapshot")
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	mf.mu.Lock()
	mf.haveWaste = true
	mf.mu.Unlock()
	done := make(chan error, 1)
	go func() { _, _, err := mf.SnapshotToFd(dst); done <- err }()
	// The clone must wait even on hosts without reflink support.
	select {
	case err := <-done:
		mf.mu.Lock()
		mf.haveWaste = false
		mf.mu.Unlock()
		t.Fatalf("snapshot returned before waste was released: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	mf.mu.Lock()
	mf.haveWaste = false
	mf.mu.Unlock()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("snapshot did not finish after waste release")
	}
}
