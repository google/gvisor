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
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/tools/nogo/flags"
)

func TestGoVersionFromModFile(t *testing.T) {
	oldVersion, oldModFile := flags.GOVERSION, flags.GOVERSIONModFile
	t.Cleanup(func() {
		flags.GOVERSION, flags.GOVERSIONModFile = oldVersion, oldModFile
	})
	for _, version := range []string{"1.21", "1.22"} {
		t.Run(version, func(t *testing.T) {
			modFile := filepath.Join(t.TempDir(), "go.mod")
			if err := os.WriteFile(modFile, []byte("module std\n\ngo "+version+" // Language version.\n"), 0600); err != nil {
				t.Fatal(err)
			}
			flags.GOVERSION, flags.GOVERSIONModFile = "", modFile
			if err := resolveGOVERSION(); err != nil {
				t.Fatal(err)
			}

			// The same go/types configuration used by Nogo must enforce the
			// module's language version, including when the SDK is newer.
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "range.go", "package p; func f() { for range 3 {} }", 0)
			if err != nil {
				t.Fatal(err)
			}
			conf := types.Config{GoVersion: flags.GOVERSION}
			_, err = conf.Check("p", fset, []*ast.File{file}, nil)
			if version == "1.21" {
				if err == nil || !strings.Contains(err.Error(), "requires go1.22 or later") {
					t.Fatalf("type check with Go %s: got %v, want integer-range version error", version, err)
				}
			} else if err != nil {
				t.Fatalf("type check with Go %s: %v", version, err)
			}
		})
	}
}

func TestGoVersionResolutionFailure(t *testing.T) {
	nogo, err := testutil.FindFile("tools/nogo/nogo")
	if err != nil {
		t.Fatal(err)
	}
	modFile := filepath.Join(t.TempDir(), "go.mod")
	if err := os.WriteFile(modFile, []byte("module std\n"), 0600); err != nil {
		t.Fatal(err)
	}
	validModFile := filepath.Join(t.TempDir(), "go.mod")
	if err := os.WriteFile(validModFile, []byte("module std\n\ngo 1.22\n"), 0600); err != nil {
		t.Fatal(err)
	}
	malformedModFile := filepath.Join(t.TempDir(), "go.mod")
	if err := os.WriteFile(malformedModFile, []byte("module std\n\ngo 1.22 extra\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "missing_file",
			args:    []string{"-GOVERSION-mod-file=" + modFile + ".missing"},
			wantErr: modFile + ".missing",
		},
		{
			name:    "missing_go_directive",
			args:    []string{"-GOVERSION-mod-file=" + modFile},
			wantErr: "go directive not found",
		},
		{
			name:    "malformed_go_directive",
			args:    []string{"-GOVERSION-mod-file=" + malformedModFile},
			wantErr: "go directive expects exactly one argument",
		},
		{
			name:    "conflicting_flags",
			args:    []string{"-GOVERSION=go1.22", "-GOVERSION-mod-file=" + validModFile},
			wantErr: "only one of -GOVERSION or -GOVERSION-mod-file may be set",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(t.Context(), nogo, append(tc.args, "help")...)
			output, err := cmd.CombinedOutput()
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("nogo %v: got %v, want exit status 1; output:\n%s", tc.args, err, output)
			}
			if !strings.Contains(string(output), "error resolving GOVERSION:") || !strings.Contains(string(output), tc.wantErr) {
				t.Fatalf("nogo %v: missing version error %q in output:\n%s", tc.args, tc.wantErr, output)
			}
		})
	}
}

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
