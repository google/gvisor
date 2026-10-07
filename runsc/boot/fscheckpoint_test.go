// Copyright 2026 The gVisor Authors.
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

package boot

import (
	"errors"
	"io"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/fscheckpoint"
)

// boundsTestCase exercises the bounds checks that protect the restore path
// against a corrupted checkpoint manifest, in which the offsets of a resource
// may point outside of the blob that holds it.
type boundsTestCase struct {
	name      string
	start     uint64
	end       uint64
	readErr   error
	expectErr bool
}

// boundsTestCases returns the cases shared by all the readers that slice a blob
// of blobLen bytes using offsets taken from the manifest.
func boundsTestCases(blobLen uint64) []boundsTestCase {
	return []boundsTestCase{
		{name: "valid range", start: 2, end: 6},
		{name: "start greater than end", start: 6, end: 2, expectErr: true},
		{name: "end beyond blob length", start: 0, end: blobLen + 10, expectErr: true},
		{name: "blob read fails", start: 0, end: 0, readErr: errors.New("read failed"), expectErr: true},
	}
}

// checkBoundsResult checks that the reader failed exactly when expected and, on
// success, that it returns blob[tc.start:tc.end].
func checkBoundsResult(t *testing.T, tc boundsTestCase, blob []byte, r io.Reader, err error) {
	t.Helper()
	if (err != nil) != tc.expectErr {
		t.Fatalf("got err = %v, expectErr = %v", err, tc.expectErr)
	}
	if tc.expectErr {
		return
	}
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("io.ReadAll() failed: %v", err)
	}
	if want := string(blob[tc.start:tc.end]); string(got) != want {
		t.Errorf("read got %q, want %q", got, want)
	}
}

// newTestFSRestore returns an fsRestore with all its maps initialized.
func newTestFSRestore() *fsRestore {
	return &fsRestore{
		mfs:          make(map[checkpoint.ResourceID]*fscheckpoint.MemoryFile),
		tmpfs:        make(map[checkpoint.ResourceID]*fscheckpoint.Tmpfs),
		fsBundles:    make(map[checkpoint.ResourceID]*fsRestoreBundle),
		waitMap:      make(map[string]*fsRestoreContainer),
		claimedMFs:   make(map[checkpoint.ResourceID]struct{}),
		claimedTmpfs: make(map[checkpoint.ResourceID]struct{}),
	}
}

func TestMemoryFileLoadArgsBounds(t *testing.T) {
	metadata := []byte("0123456789") // len = 10
	resID := checkpoint.ResourceID{ContainerName: "c1", Path: "/dev/shm"}

	for _, tc := range boundsTestCases(uint64(len(metadata))) {
		t.Run(tc.name, func(t *testing.T) {
			fsr := newTestFSRestore()
			fsr.mfs[resID] = &fscheckpoint.MemoryFile{
				ResourceID:         resID,
				PagesMetadataStart: tc.start,
				PagesMetadataEnd:   tc.end,
			}
			fsr.fsBundles[resID] = &fsRestoreBundle{
				getPagesMetadata: func() ([]byte, error) {
					if tc.readErr != nil {
						return nil, tc.readErr
					}
					return metadata, nil
				},
			}
			r, _, err := fsr.memoryFileLoadArgs(resID, "c1")
			checkBoundsResult(t, tc, metadata, r, err)
			if _, claimed := fsr.claimedMFs[resID]; claimed != !tc.expectErr {
				t.Errorf("claimedMFs[%v] = %v, want %v", resID, claimed, !tc.expectErr)
			}
		})
	}
}

// TestMemoryFileLoadArgsUnalignedPages checks that a pages offset that is not
// page aligned is rejected, since the memory file can't be loaded from it.
func TestMemoryFileLoadArgsUnalignedPages(t *testing.T) {
	metadata := []byte("0123456789")
	resID := checkpoint.ResourceID{ContainerName: "c1", Path: "/dev/shm"}

	fsr := newTestFSRestore()
	fsr.mfs[resID] = &fscheckpoint.MemoryFile{
		ResourceID:         resID,
		PagesMetadataStart: 0,
		PagesMetadataEnd:   5,
		PagesStart:         123,
	}
	fsr.fsBundles[resID] = &fsRestoreBundle{
		getPagesMetadata: func() ([]byte, error) { return metadata, nil },
	}

	if _, _, err := fsr.memoryFileLoadArgs(resID, "c1"); err == nil {
		t.Errorf("memoryFileLoadArgs() with unaligned pages start succeeded, want error")
	}
	if _, claimed := fsr.claimedMFs[resID]; claimed {
		t.Errorf("claimedMFs[%v] = true after unaligned error, want false", resID)
	}
}

func TestTmpfsSourceTarBounds(t *testing.T) {
	tarData := []byte("0123456789abcdefghij") // len = 20
	resID := checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp"}

	for _, tc := range boundsTestCases(uint64(len(tarData))) {
		t.Run(tc.name, func(t *testing.T) {
			fsr := newTestFSRestore()
			fsr.tmpfs[resID] = &fscheckpoint.Tmpfs{
				ResourceID: resID,
				TarStart:   tc.start,
				TarEnd:     tc.end,
			}
			fsr.fsBundles[resID] = &fsRestoreBundle{
				getMultiTar: func() ([]byte, error) {
					if tc.readErr != nil {
						return nil, tc.readErr
					}
					return tarData, nil
				},
			}
			rc, err := fsr.tmpfsSourceTar(resID, "c1")
			checkBoundsResult(t, tc, tarData, rc, err)
			if _, claimed := fsr.claimedTmpfs[resID]; claimed != !tc.expectErr {
				t.Errorf("claimedTmpfs[%v] = %v, want %v", resID, claimed, !tc.expectErr)
			}
		})
	}
}

func TestUnmappedBundleError(t *testing.T) {
	resID := checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp"}
	fsr := newTestFSRestore()
	fsr.mfs[resID] = &fscheckpoint.MemoryFile{ResourceID: resID}
	fsr.tmpfs[resID] = &fscheckpoint.Tmpfs{ResourceID: resID}

	if _, _, err := fsr.memoryFileLoadArgs(resID, "c1"); err == nil {
		t.Errorf("memoryFileLoadArgs() with unmapped bundle succeeded, want error")
	}
	if _, err := fsr.tmpfsSourceTar(resID, "c1"); err == nil {
		t.Errorf("tmpfsSourceTar() with unmapped bundle succeeded, want error")
	}
}

func TestMakeFSRestoreOptsForLocalCheckpointInvalidFDCounts(t *testing.T) {
	for _, count := range []int{0, 1, 3, 5, 7} {
		args := &Args{FSRestoreFDs: make([]*fd.FD, count)}
		if _, err := makeFSRestoreOptsForLocalCheckpoint(args); err == nil {
			t.Errorf("makeFSRestoreOptsForLocalCheckpoint(%d FDs) = nil, want error", count)
		}
	}
}

func TestAddRestoreEntryDuplicates(t *testing.T) {
	m := make(map[checkpoint.ResourceID]int)
	tmpfsMap := make(map[checkpoint.ResourceID]int)
	fsBundles := make(map[checkpoint.ResourceID]*fsRestoreBundle)
	b1 := &fsRestoreBundle{}
	b2 := &fsRestoreBundle{}
	c1Data := checkpoint.ResourceID{ContainerName: "c1", Path: "/data"}
	c2Data := checkpoint.ResourceID{ContainerName: "c2", Path: "/data"}

	if err := addRestoreEntry(m, fsBundles, c1Data, 1, b1, "MemoryFile"); err != nil {
		t.Fatalf("addRestoreEntry(%v) failed: %v", c1Data, err)
	}
	if err := addRestoreEntry(m, fsBundles, c2Data, 2, b1, "MemoryFile"); err != nil {
		t.Fatalf("addRestoreEntry(%v) failed: %v", c2Data, err)
	}
	if err := addRestoreEntry(m, fsBundles, c1Data, 3, b1, "MemoryFile"); err == nil || !strings.Contains(err.Error(), "duplicate MemoryFile") {
		t.Errorf("addRestoreEntry(%v) error = %v, want duplicate MemoryFile error", c1Data, err)
	}
	// Same ResourceID across different bundles (e.g. MemoryFile in b1, Tmpfs in b2) should fail.
	if err := addRestoreEntry(tmpfsMap, fsBundles, c1Data, 4, b2, "Tmpfs"); err == nil || !strings.Contains(err.Error(), "multiple filesystem checkpoint bundles") {
		t.Errorf("addRestoreEntry(%v) across bundles error = %v, want multiple bundles error", c1Data, err)
	}
}
