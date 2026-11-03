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

package container

import (
	"os"
	"strings"
	"testing"
)

func writeStateFile(t *testing.T, rootDir string, id FullID) {
	t.Helper()
	if err := os.WriteFile(buildPath(rootDir, id, stateFileExtension), []byte("{}"), 0640); err != nil {
		t.Fatalf("writing state file: %v", err)
	}
}

func TestFindContainerID(t *testing.T) {
	rootDir := t.TempDir()
	for _, id := range []FullID{
		{SandboxID: "abc", ContainerID: "abc"},
		{SandboxID: "abcd", ContainerID: "abcd"},
		{SandboxID: "pod", ContainerID: "ctr1"},
	} {
		writeStateFile(t, rootDir, id)
	}
	for _, tc := range []struct {
		partial string
		want    FullID
		wantErr string
	}{
		// A full root container ID matches exactly, though it also prefixes
		// "abcd".
		{partial: "abc", want: FullID{SandboxID: "abc", ContainerID: "abc"}},
		{partial: "abcd", want: FullID{SandboxID: "abcd", ContainerID: "abcd"}},
		{partial: "ab", wantErr: "ambiguous"},
		{partial: "ctr1", want: FullID{SandboxID: "pod", ContainerID: "ctr1"}},
		{partial: "ctr", want: FullID{SandboxID: "pod", ContainerID: "ctr1"}},
		{partial: "missing", wantErr: os.ErrNotExist.Error()},
	} {
		got, err := findContainerID(rootDir, tc.partial)
		if tc.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("findContainerID(%q) = %v, %v, want error containing %q", tc.partial, got, err, tc.wantErr)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("findContainerID(%q) = %v, %v, want %v", tc.partial, got, err, tc.want)
		}
	}
}
