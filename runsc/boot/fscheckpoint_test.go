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
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/checkpoint"
	"gvisor.dev/gvisor/pkg/sentry/fscheckpoint"
)

func TestParseFSCheckpointPaths(t *testing.T) {
	testCases := []struct {
		name      string
		input     string
		want      []checkpoint.ResourceID
		expectErr bool
	}{
		{
			name:  "empty string",
			input: "",
			want:  nil,
		},
		{
			name:  "whitespace-only string",
			input: "   ",
			want:  nil,
		},
		{
			name:  "single clean path",
			input: "/tmp",
			want:  []checkpoint.ResourceID{{Path: "/tmp"}},
		},
		{
			name:  "trailing slash cleaned",
			input: "/tmp/",
			want:  []checkpoint.ResourceID{{Path: "/tmp"}},
		},
		{
			name:  "multiple paths with spaces and redundant slashes",
			input: " /tmp/ , /var//run/. , / ",
			want: []checkpoint.ResourceID{
				{Path: "/tmp"},
				{Path: "/var/run"},
				{Path: "/"},
			},
		},
		{
			name:  "container prefixed paths",
			input: "c1:/tmp/ , c2:/data/app/..",
			want: []checkpoint.ResourceID{
				{ContainerName: "c1", Path: "/tmp"},
				{ContainerName: "c2", Path: "/data"},
			},
		},
		{
			name:  "all-tmpfs keyword",
			input: "all-tmpfs, c1:all-tmpfs",
			want: []checkpoint.ResourceID{
				{Path: "all-tmpfs"},
				{ContainerName: "c1", Path: "all-tmpfs"},
			},
		},
		{
			name:      "empty container path error",
			input:     "c1:",
			expectErr: true,
		},
		{
			name:      "relative path error",
			input:     "tmp",
			expectErr: true,
		},
		{
			name:      "relative path with container error",
			input:     "c1:tmp",
			expectErr: true,
		},
		{
			name:      "relative path in multi-path error",
			input:     "/tmp, var/run",
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseFSCheckpointPaths(tc.input)
			if (err != nil) != tc.expectErr {
				t.Fatalf("ParseFSCheckpointPaths(%q) err = %v, expectErr = %v", tc.input, err, tc.expectErr)
			}
			if !tc.expectErr && !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ParseFSCheckpointPaths(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

type testResource struct {
	id    checkpoint.ResourceID
	value string
}

func TestFindByResourceID(t *testing.T) {
	testCases := []struct {
		name      string
		entries   []testResource
		query     checkpoint.ResourceID
		wantVal   string
		wantFound bool
	}{
		{
			name: "exact match container and path",
			entries: []testResource{
				{id: checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp"}, value: "val1"},
			},
			query:     checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp"},
			wantVal:   "val1",
			wantFound: true,
		},
		{
			name: "fallback match when query container name is empty",
			entries: []testResource{
				{id: checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp"}, value: "val1"},
			},
			query:     checkpoint.ResourceID{ContainerName: "", Path: "/tmp"},
			wantVal:   "val1",
			wantFound: true,
		},
		{
			name: "fallback match when entry container name is empty",
			entries: []testResource{
				{id: checkpoint.ResourceID{ContainerName: "", Path: "/tmp"}, value: "val1"},
			},
			query:     checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp"},
			wantVal:   "val1",
			wantFound: true,
		},
		{
			name: "rejection when container names conflict",
			entries: []testResource{
				{id: checkpoint.ResourceID{ContainerName: "c2", Path: "/tmp"}, value: "val2"},
			},
			query:     checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp"},
			wantFound: false,
		},
		{
			name: "rejection when ambiguous multiple matches",
			entries: []testResource{
				{id: checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp"}, value: "val1"},
				{id: checkpoint.ResourceID{ContainerName: "c2", Path: "/tmp"}, value: "val2"},
			},
			query:     checkpoint.ResourceID{ContainerName: "", Path: "/tmp"},
			wantFound: false,
		},
		{
			name: "rejection when path does not exist",
			entries: []testResource{
				{id: checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp"}, value: "val1"},
			},
			query:     checkpoint.ResourceID{ContainerName: "c1", Path: "/var"},
			wantFound: false,
		},
		{
			name: "exact match with trailing slash in query",
			entries: []testResource{
				{id: checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp"}, value: "val1"},
			},
			query:     checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp/"},
			wantVal:   "val1",
			wantFound: true,
		},
		{
			name: "fallback match with trailing slash in query and entry",
			entries: []testResource{
				{id: checkpoint.ResourceID{ContainerName: "", Path: "/tmp/"}, value: "val1"},
			},
			query:     checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp"},
			wantVal:   "val1",
			wantFound: true,
		},
		{
			name: "match when entry has trailing slash and both have container name",
			entries: []testResource{
				{id: checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp/"}, value: "val1"},
			},
			query:     checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp"},
			wantVal:   "val1",
			wantFound: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			m := make(map[checkpoint.ResourceID]*testResource)
			for i := range tc.entries {
				m[tc.entries[i].id] = &tc.entries[i]
			}
			got, found := findByResourceID(m, tc.query, func(r *testResource) checkpoint.ResourceID {
				return r.id
			}, "testResource")

			if found != tc.wantFound {
				t.Fatalf("findByResourceID found = %v, wantFound = %v", found, tc.wantFound)
			}
			if tc.wantFound && got.value != tc.wantVal {
				t.Errorf("findByResourceID got value = %q, want %q", got.value, tc.wantVal)
			}
		})
	}
}

func TestMemoryFileLoadArgsBounds(t *testing.T) {
	metadata := []byte("0123456789") // len = 10
	resID := checkpoint.ResourceID{ContainerName: "c1", Path: "/dev/shm"}

	testCases := []struct {
		name       string
		start      uint64
		end        uint64
		pagesStart uint64
		readErr    error
		expectErr  bool
	}{
		{
			name:      "valid range",
			start:     2,
			end:       6,
			expectErr: false,
		},
		{
			name:      "start greater than end",
			start:     6,
			end:       2,
			expectErr: true,
		},
		{
			name:      "end beyond slice length",
			start:     0,
			end:       20,
			expectErr: true,
		},
		{
			name:      "start greater than end and end beyond length",
			start:     30,
			end:       20,
			expectErr: true,
		},
		{
			name:       "unaligned pages start",
			start:      0,
			end:        5,
			pagesStart: 123,
			expectErr:  true,
		},
		{
			name:      "read error with empty bounds",
			start:     0,
			end:       0,
			readErr:   errors.New("metadata read failed"),
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fsr := &fsRestore{
				mfs: map[checkpoint.ResourceID]*fscheckpoint.MemoryFile{
					resID: {
						ResourceID:         resID,
						PagesMetadataStart: tc.start,
						PagesMetadataEnd:   tc.end,
						PagesStart:         tc.pagesStart,
					},
				},
				tmpfs:   make(map[checkpoint.ResourceID]*fscheckpoint.Tmpfs),
				waitMap: make(map[string]*fsRestoreContainer),
				getPagesMetadata: func() ([]byte, error) {
					if tc.readErr != nil {
						return nil, tc.readErr
					}
					return metadata, nil
				},
			}
			r, _, _, err := fsr.memoryFileLoadArgs(resID, "c1")
			if (err != nil) != tc.expectErr {
				t.Fatalf("memoryFileLoadArgs() err = %v, expectErr = %v", err, tc.expectErr)
			}
			if !tc.expectErr {
				got, err := io.ReadAll(r)
				if err != nil {
					t.Fatalf("io.ReadAll() err = %v", err)
				}
				if string(got) != string(metadata[tc.start:tc.end]) {
					t.Errorf("read got %q, want %q", got, metadata[tc.start:tc.end])
				}
			}
		})
	}
}

func TestTmpfsSourceTarBounds(t *testing.T) {
	tarData := []byte("0123456789abcdefghij") // len = 20
	resID := checkpoint.ResourceID{ContainerName: "c1", Path: "/tmp"}

	testCases := []struct {
		name      string
		start     uint64
		end       uint64
		readErr   error
		expectErr bool
	}{
		{
			name:      "valid range",
			start:     2,
			end:       6,
			expectErr: false,
		},
		{
			name:      "start greater than end with end zero",
			start:     10,
			end:       0,
			expectErr: true,
		},
		{
			name:      "start greater than end within len",
			start:     15,
			end:       10,
			expectErr: true,
		},
		{
			name:      "end beyond slice length",
			start:     0,
			end:       50,
			expectErr: true,
		},
		{
			name:      "start greater than end and end beyond length",
			start:     60,
			end:       50,
			expectErr: true,
		},
		{
			name:      "read error with empty bounds",
			start:     0,
			end:       0,
			readErr:   errors.New("tar read failed"),
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fsr := &fsRestore{
				mfs: make(map[checkpoint.ResourceID]*fscheckpoint.MemoryFile),
				tmpfs: map[checkpoint.ResourceID]*fscheckpoint.Tmpfs{
					resID: {
						ResourceID: resID,
						TarStart:   tc.start,
						TarEnd:     tc.end,
					},
				},
				waitMap: make(map[string]*fsRestoreContainer),
				getMultiTar: func() ([]byte, error) {
					if tc.readErr != nil {
						return nil, tc.readErr
					}
					return tarData, nil
				},
			}
			rc, err := fsr.tmpfsSourceTar(resID, "c1")
			if (err != nil) != tc.expectErr {
				t.Fatalf("tmpfsSourceTar() err = %v, expectErr = %v", err, tc.expectErr)
			}
			if !tc.expectErr {
				got, err := io.ReadAll(rc)
				if err != nil {
					t.Fatalf("io.ReadAll() err = %v", err)
				}
				if string(got) != string(tarData[tc.start:tc.end]) {
					t.Errorf("read got %q, want %q", got, tarData[tc.start:tc.end])
				}
			}
		})
	}
}

func TestGetFSTarBoundsCheck(t *testing.T) {
	testCases := []struct {
		name      string
		tarStart  uint64
		tarEnd    uint64
		tarLen    int
		expectErr bool
	}{
		{
			name:      "valid range",
			tarStart:  0,
			tarEnd:    10,
			tarLen:    20,
			expectErr: false,
		},
		{
			name:      "empty range at start",
			tarStart:  0,
			tarEnd:    0,
			tarLen:    20,
			expectErr: false,
		},
		{
			name:      "exact bounds match",
			tarStart:  0,
			tarEnd:    20,
			tarLen:    20,
			expectErr: false,
		},
		{
			name:      "inverted bounds start greater than end",
			tarStart:  15,
			tarEnd:    10,
			tarLen:    20,
			expectErr: true,
		},
		{
			name:      "tar end beyond slice length",
			tarStart:  0,
			tarEnd:    25,
			tarLen:    20,
			expectErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resID := checkpoint.ResourceID{Path: "/tmp"}
			fsr := &fsRestore{
				tmpfs: map[checkpoint.ResourceID]*fscheckpoint.Tmpfs{
					resID: {
						ResourceID: resID,
						TarStart:   tc.tarStart,
						TarEnd:     tc.tarEnd,
					},
				},
				getMultiTar: func() ([]byte, error) {
					return make([]byte, tc.tarLen), nil
				},
			}

			rc, err := fsr.GetFSTar(resID)
			if (err != nil) != tc.expectErr {
				t.Fatalf("GetFSTar() err = %v, expectErr = %v", err, tc.expectErr)
			}
			if !tc.expectErr {
				if rc == nil {
					t.Fatalf("GetFSTar() returned nil reader, want non-nil")
				}
				rc.Close()
			}
		})
	}
}
