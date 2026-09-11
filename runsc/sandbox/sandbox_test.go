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

package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGetGCSURIFromImagePath(t *testing.T) {
	tmpDir := t.TempDir()

	testCases := []struct {
		name      string
		content   string
		writeOpts bool
		want      string
	}{
		{
			name:      "missing file",
			writeOpts: false,
			want:      "",
		},
		{
			name:      "invalid json",
			content:   "not valid json",
			writeOpts: true,
			want:      "",
		},
		{
			name:      "empty bucket",
			content:   `{"bucket": ""}`,
			writeOpts: true,
			want:      "",
		},
		{
			name:      "bucket only",
			content:   `{"bucket": "my-test-bucket"}`,
			writeOpts: true,
			want:      "gs://my-test-bucket",
		},
		{
			name:      "bucket with object prefix",
			content:   `{"bucket": "my-test-bucket", "object_prefix": "snapshots/test/"}`,
			writeOpts: true,
			want:      "gs://my-test-bucket/snapshots/test/",
		},
		{
			name:      "bucket with leading slash in object prefix",
			content:   `{"bucket": "my-test-bucket", "object_prefix": "/snapshots/test/"}`,
			writeOpts: true,
			want:      "gs://my-test-bucket/snapshots/test/",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			subDir := filepath.Join(tmpDir, tc.name)
			if err := os.MkdirAll(subDir, 0755); err != nil {
				t.Fatalf("failed to create directory: %v", err)
			}
			if tc.writeOpts {
				optsPath := filepath.Join(subDir, checkpointGCSOptsFileName)
				if err := os.WriteFile(optsPath, []byte(tc.content), 0644); err != nil {
					t.Fatalf("failed to write %s: %v", optsPath, err)
				}
			}
			got := getGCSURIFromImagePath(subDir)
			if got != tc.want {
				t.Errorf("getGCSURIFromImagePath(%q) = %q, want %q", subDir, got, tc.want)
			}
		})
	}
}
