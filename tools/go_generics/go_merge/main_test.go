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
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gvisor.dev/gvisor/tools/constraintutil"
)

func writeSources(t *testing.T, sources ...string) []string {
	t.Helper()
	dir := t.TempDir()
	var paths []string
	for i, source := range sources {
		path := filepath.Join(dir, fmt.Sprintf("%d.go", i))
		if err := os.WriteFile(path, []byte(source), 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return paths
}

func TestMergeDeclarations(t *testing.T) {
	paths := writeSources(t, `package merged
var Calls int
func init() { Calls++ }
type First[T any] struct{}
func (First[T]) Value() int { return 1 }
`, `package merged
func init() { Calls += 2 }
type Second[T any] struct{}
func (*Second[T]) Value() int { return 2 }
func Value() int { return 3 }
`)
	source, err := merge(paths)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "merged.go", source, 0)
	if err != nil {
		t.Fatalf("ParseFile: %v\n%s", err, source)
	}
	var config types.Config
	if _, err := config.Check("merged", fset, []*ast.File{file}, nil); err != nil {
		t.Fatalf("type checking merged source: %v\n%s", err, source)
	}
	var names []string
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			names = append(names, fn.Name.Name)
		}
	}
	if got, want := names, []string{"init", "Value", "init", "Value", "Value"}; !slices.Equal(got, want) {
		t.Errorf("merged functions = %v, want %v\n%s", got, want, source)
	}
	slices.Reverse(paths)
	reversed, err := merge(paths)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(source, reversed) {
		t.Errorf("argument order changed output:\n%s\nversus:\n%s", source, reversed)
	}
}

func TestMergeImportsCommentsAndConstraints(t *testing.T) {
	paths := writeSources(t, `//go:build linux

// Package merged is template documentation.
package merged

import (
	"fmt" // first named import.
	_ "os" // first blank import.
)

// Answer is shared.
const Answer = 42

// +stateify savable
type Saved struct{}

func early() string {
	return fmt.Sprint(Answer) // escapes: keep with early.
}
`, `//go:build amd64

package merged

import "fmt" // duplicate named import.
import alias "strings" // later named import.
import _ "os" // second blank import.

//go:noinline
func late() string {
	return alias.TrimSpace(early()) // escapes: keep with late.
}
`)
	slices.Reverse(paths)
	source, err := merge(paths)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"// Answer is shared.\nconst Answer = 42",
		"// +stateify savable\ntype Saved struct{}",
		"return fmt.Sprint(Answer) // escapes: keep with early.",
		"//go:noinline\nfunc late() string",
		"return alias.TrimSpace(early()) // escapes: keep with late.",
	} {
		if !strings.Contains(string(source), want) {
			t.Errorf("merged source lacks %q:\n%s", want, source)
		}
	}
	for _, unwanted := range []string{"template documentation", "duplicate named import"} {
		if strings.Contains(string(source), unwanted) {
			t.Errorf("merged source contains %q:\n%s", unwanted, source)
		}
	}
	file, err := parser.ParseFile(token.NewFileSet(), "merged.go", source, parser.ParseComments)
	if err != nil {
		t.Fatalf("ParseFile: %v\n%s", err, source)
	}
	wantImports := []struct {
		name    string
		path    string
		comment string
	}{
		{"", `"fmt"`, "first named import.\n"},
		{"_", `"os"`, "first blank import.\n"},
		{"alias", `"strings"`, "later named import.\n"},
		{"_", `"os"`, "second blank import.\n"},
	}
	if len(file.Imports) != len(wantImports) {
		t.Fatalf("merged imports = %d, want %d\n%s", len(file.Imports), len(wantImports), source)
	}
	for i, want := range wantImports {
		got := file.Imports[i]
		var name string
		if got.Name != nil {
			name = got.Name.Name
		}
		if name != want.name || got.Path.Value != want.path || got.Comment.Text() != want.comment {
			t.Errorf("import %d = %q %s %q, want %q %s %q", i, name, got.Path.Value, got.Comment.Text(), want.name, want.path, want.comment)
		}
	}
	expr, err := constraintutil.FromString(string(source))
	if err != nil || expr == nil {
		t.Fatalf("merged build constraint = %v, %v", expr, err)
	}
	for _, tags := range [][]string{{"linux", "amd64"}, {"linux", "arm64"}, {"darwin", "amd64"}} {
		got := expr.Eval(func(tag string) bool { return slices.Contains(tags, tag) })
		want := slices.Equal(tags, []string{"linux", "amd64"})
		if got != want {
			t.Errorf("constraint %s with %v = %t, want %t", expr, tags, got, want)
		}
	}
}

func TestMergeErrors(t *testing.T) {
	for _, test := range []struct {
		name   string
		first  string
		second string
		want   string
	}{
		{
			name:   "package mismatch",
			first:  "package first",
			second: "package second",
			want:   `expected "first" for package name instead of "second"`,
		},
		{
			name:   "import name conflict",
			first:  "package merged; import shared \"example.com/first\"",
			second: "package merged; import shared \"example.com/second\"",
			want:   `conflicting paths for import name "shared"`,
		},
		{
			name:   "invalid source",
			first:  "package merged; func {",
			second: "package merged",
			want:   "expected",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := merge(writeSources(t, test.first, test.second))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("merge error = %v, want containing %q", err, test.want)
			}
		})
	}
}
