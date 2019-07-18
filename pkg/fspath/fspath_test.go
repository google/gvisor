// Copyright 2019 The gVisor Authors.
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

package fspath

import (
	"reflect"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/syserror"
)

func TestParseIteratorPartialPathnames(t *testing.T) {
	path, err := Parse("/foo//bar///baz////")
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}
	// Parse strips leading slashes, and records their presence as
	// Path.Absolute.
	if !path.Absolute {
		t.Errorf("Path.Absolute: got false, wanted true")
	}
	// Parse strips trailing slashes, and records their presence as Path.Dir.
	if !path.Dir {
		t.Errorf("Path.Dir: got false, wanted true")
	}
	// The first Iterator.partialPathname is the input pathname, with leading
	// and trailing slashes stripped.
	it := path.Begin
	if want := "foo//bar///baz"; it.partialPathname != want {
		t.Errorf("first Iterator.partialPathname: got %q, wanted %q", it.partialPathname, want)
	}
	// Successive Iterator.partialPathnames remove the leading path component
	// and following slashes, until we run out of path components and get a
	// terminal Iterator.
	it = it.Next()
	if want := "bar///baz"; it.partialPathname != want {
		t.Errorf("second Iterator.partialPathname: got %q, wanted %q", it.partialPathname, want)
	}
	it = it.Next()
	if want := "baz"; it.partialPathname != want {
		t.Errorf("third Iterator.partialPathname: got %q, wanted %q", it.partialPathname, want)
	}
	it = it.Next()
	if want := ""; it.partialPathname != want {
		t.Errorf("fourth Iterator.partialPathname: got %q, wanted %q", it.partialPathname, want)
	}
	if it.Ok() {
		t.Errorf("fourth Iterator.Ok(): got true, wanted false")
	}
}

func TestParse(t *testing.T) {
	type testCase struct {
		pathname string
		relpath  []string
		abs      bool
		dir      bool
	}
	tests := []testCase{
		{
			pathname: "/",
			relpath:  []string{},
			abs:      true,
			dir:      true,
		},
		{
			pathname: "//",
			relpath:  []string{},
			abs:      true,
			dir:      true,
		},
	}
	for _, sep := range []string{"/", "//"} {
		for _, abs := range []bool{false, true} {
			for _, dir := range []bool{false, true} {
				for _, pcs := range [][]string{
					// single path component
					{"foo"},
					// multiple path components, including non-UTF-8
					{".", "foo", "..", "\xe6", "bar"},
				} {
					prefix := ""
					if abs {
						prefix = sep
					}
					suffix := ""
					if dir {
						suffix = sep
					}
					tests = append(tests, testCase{
						pathname: prefix + strings.Join(pcs, sep) + suffix,
						relpath:  pcs,
						abs:      abs,
						dir:      dir,
					})
				}
			}
		}
	}

	for _, test := range tests {
		t.Run(test.pathname, func(t *testing.T) {
			p, err := Parse(test.pathname)
			if err != nil {
				t.Fatalf("failed to parse pathname %q: %v", test.pathname, err)
			}
			t.Logf("pathname %q => path %q", test.pathname, p)
			if p.Absolute != test.abs {
				t.Errorf("path absoluteness: got %v, wanted %v", p.Absolute, test.abs)
			}
			if p.Dir != test.dir {
				t.Errorf("path must resolve to a directory: got %v, wanted %v", p.Dir, test.dir)
			}
			pcs := []string{}
			for pit := p.Begin; pit.Ok(); pit = pit.Next() {
				pcs = append(pcs, pit.String())
			}
			if !reflect.DeepEqual(pcs, test.relpath) {
				t.Errorf("relative path: got %v, wanted %v", pcs, test.relpath)
			}
		})
	}
}

func TestParseEmptyPathname(t *testing.T) {
	p, err := Parse("")
	if err != syserror.ENOENT {
		t.Errorf("parsing empty pathname: got (%v, %v), wanted (<unspecified>, ENOENT)", p, err)
	}
}
