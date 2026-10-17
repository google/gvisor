// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package gvisorbinaries

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirForExecutable(t *testing.T) {
	for _, name := range []string{"Adjacent", "LinkTarget", "LinkNeighbor", "Override", "Missing"} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(sidecarBinariesDirEnv, "")
			exe := filepath.Join(t.TempDir(), "runsc")
			if err := os.WriteFile(exe, nil, 0o755); err != nil {
				t.Fatal(err)
			}
			want := filepath.Join(filepath.Dir(exe), binDirName)
			if name == "LinkTarget" || name == "LinkNeighbor" {
				link := filepath.Join(t.TempDir(), "runsc")
				if err := os.Symlink(exe, link); err != nil {
					t.Fatal(err)
				}
				exe = link
				if name == "LinkNeighbor" {
					want = filepath.Join(filepath.Dir(link), binDirName)
				}
			}
			if name == "Override" {
				want = t.TempDir()
				t.Setenv(sidecarBinariesDirEnv, want)
			}
			if name == "Adjacent" || name == "LinkNeighbor" {
				if err := os.Mkdir(want, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if name == "Missing" {
				exe = filepath.Join(t.TempDir(), "missing")
			}
			got, err := DirForExecutable(exe)
			if name == "Missing" {
				if err == nil {
					t.Fatal("resolved a nonexistent executable")
				}
			} else if err != nil || got != want {
				t.Fatalf("DirForExecutable = %q, %v, want %q", got, err, want)
			}
		})
	}
}
