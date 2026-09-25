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
	"testing"

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
		mfs:     make(map[checkpoint.ResourceID]*fscheckpoint.MemoryFile),
		tmpfs:   make(map[checkpoint.ResourceID]*fscheckpoint.Tmpfs),
		waitMap: make(map[string]*fsRestoreContainer),
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
			fsr.getPagesMetadata = func() ([]byte, error) {
				if tc.readErr != nil {
					return nil, tc.readErr
				}
				return metadata, nil
			}
			r, _, _, err := fsr.memoryFileLoadArgs(resID, "c1")
			checkBoundsResult(t, tc, metadata, r, err)
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
	fsr.getPagesMetadata = func() ([]byte, error) { return metadata, nil }

	if _, _, _, err := fsr.memoryFileLoadArgs(resID, "c1"); err == nil {
		t.Errorf("memoryFileLoadArgs() with unaligned pages start succeeded, want error")
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
			fsr.getMultiTar = func() ([]byte, error) {
				if tc.readErr != nil {
					return nil, tc.readErr
				}
				return tarData, nil
			}
			rc, err := fsr.tmpfsSourceTar(resID, "c1")
			checkBoundsResult(t, tc, tarData, rc, err)
		})
	}
}
