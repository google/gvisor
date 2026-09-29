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

package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAssemble(t *testing.T) {
	root := t.TempDir()
	gopath := filepath.Join(root, "gopath.zip")
	var input bytes.Buffer
	archive := zip.NewWriter(&input)
	for _, name := range []string{"src/example.com/m/command.go", "src/other/pkg.go", "src/example.com/m/pkg.go"} {
		h := &zip.FileHeader{Name: name}
		h.SetMode(0o755)
		entry, err := archive.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte("library source")); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(gopath, input.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	goMod := filepath.Join(root, "go.mod")
	command := filepath.Join(root, "command.go")
	if err := os.WriteFile(command, []byte("command source"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, module, wantError string
	}{
		{
			name:   "quoted module with comments and whitespace",
			module: "// module declaration\nmodule\t\"example.com/m\" // comment\n",
		},
		{name: "invalid module", module: "module a b\n", wantError: "usage: module module/path"},
		{name: "missing module", module: "go 1.26\n", wantError: "has no module directive"},
		{name: "absent sources", module: "module example.com/absent\n", wantError: "contains no sources"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(goMod, []byte(tc.module), 0o644); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			err := assemble(gopath, goMod, []string{command}, &output)
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("assemble error = %v, want %q", err, tc.wantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got, err := zip.NewReader(bytes.NewReader(output.Bytes()), int64(output.Len()))
			if err != nil {
				t.Fatal(err)
			}
			want := map[string]string{
				"README.md":  readme,
				"command.go": "command source",
				"go.mod":     tc.module,
				"pkg.go":     "library source",
			}
			if len(got.File) != len(want) {
				t.Fatalf("archive entries = %d, want %d", len(got.File), len(want))
			}
			var names []string
			for _, entry := range got.File {
				names = append(names, entry.Name)
				content, err := readEntry(entry)
				if err != nil {
					t.Fatal(err)
				}
				if expected, ok := want[entry.Name]; !ok || string(content) != expected {
					t.Errorf("entry %q = %q, want %q (expected=%t)", entry.Name, content, expected, ok)
				}
				if entry.Mode() != 0o644 || !entry.Modified.Equal(time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)) {
					t.Errorf("entry %q metadata = %v, %v; want 0644, 1980-01-01 UTC", entry.Name, entry.Mode(), entry.Modified)
				}
			}
			if !slices.IsSorted(names) {
				t.Errorf("archive entries are not sorted: %v", names)
			}
			var repeated bytes.Buffer
			if err := assemble(gopath, goMod, []string{command}, &repeated); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(output.Bytes(), repeated.Bytes()) {
				t.Error("assembling the same inputs produced different ZIP bytes")
			}
		})
	}
}
