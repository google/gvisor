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

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"gvisor.dev/gvisor/tools/nogo/flags"
)

func TestResolveGOVERSION(t *testing.T) {
	oldVersion, oldModFile := flags.GOVERSION, flags.GOVERSIONModFile
	t.Cleanup(func() {
		flags.GOVERSION, flags.GOVERSIONModFile = oldVersion, oldModFile
	})
	for _, tc := range []struct {
		name, contents, want string
	}{
		{"stdlib", "module std\n\ngo 1.26\n", "go1.26"},
		{"comments-and-crlf", "// Header.\r\nmodule std\r\ngo\t1.26\r\n", "go1.26"},
		{"missing", "module std\n", ""},
		{"split-directive", "module std\ngo\n1.26\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modFile := filepath.Join(t.TempDir(), "go.mod")
			if err := os.WriteFile(modFile, []byte(tc.contents), 0644); err != nil {
				t.Fatal(err)
			}
			flags.GOVERSION = ""
			flags.GOVERSIONModFile = modFile
			if err := resolveGOVERSION(); err != nil {
				if tc.want != "" {
					t.Fatalf("resolveGOVERSION: %v", err)
				}
				return
			}
			if tc.want == "" {
				t.Fatal("resolveGOVERSION succeeded without a valid go directive")
			}
			if got := flags.GOVERSION; got != tc.want {
				t.Errorf("GOVERSION = %q, want %q", got, tc.want)
			}
		})
	}
}
