// Copyright 2018 Google Inc.
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

package fs

import (
	"testing"
)

// TestSplitLast tests variants of path splitting.
func TestSplitLast(t *testing.T) {
	cases := []struct {
		path string
		dir  string
		file string
	}{
		{path: "/", dir: "/", file: "."},
		{path: "/.", dir: "/", file: "."},
		{path: "/./", dir: "/", file: "."},
		{path: "/./.", dir: "/.", file: "."},
		{path: "/././", dir: "/.", file: "."},
		{path: "/./..", dir: "/.", file: ".."},
		{path: "/./../", dir: "/.", file: ".."},
		{path: "/..", dir: "/", file: ".."},
		{path: "/../", dir: "/", file: ".."},
		{path: "/../.", dir: "/..", file: "."},
		{path: "/.././", dir: "/..", file: "."},
		{path: "/../..", dir: "/..", file: ".."},
		{path: "/../../", dir: "/..", file: ".."},

		{path: "", dir: ".", file: "."},
		{path: ".", dir: ".", file: "."},
		{path: "./", dir: ".", file: "."},
		{path: "./.", dir: ".", file: "."},
		{path: "././", dir: ".", file: "."},
		{path: "./..", dir: ".", file: ".."},
		{path: "./../", dir: ".", file: ".."},
		{path: "..", dir: ".", file: ".."},
		{path: "../", dir: ".", file: ".."},
		{path: "../.", dir: "..", file: "."},
		{path: ".././", dir: "..", file: "."},
		{path: "../..", dir: "..", file: ".."},
		{path: "../../", dir: "..", file: ".."},

		{path: "/foo", dir: "/", file: "foo"},
		{path: "/foo/", dir: "/", file: "foo"},
		{path: "/foo/.", dir: "/foo", file: "."},
		{path: "/foo/./", dir: "/foo", file: "."},
		{path: "/foo/./.", dir: "/foo/.", file: "."},
		{path: "/foo/./..", dir: "/foo/.", file: ".."},
		{path: "/foo/..", dir: "/foo", file: ".."},
		{path: "/foo/../", dir: "/foo", file: ".."},
		{path: "/foo/../.", dir: "/foo/..", file: "."},
		{path: "/foo/../..", dir: "/foo/..", file: ".."},

		{path: "/foo/bar", dir: "/foo", file: "bar"},
		{path: "/foo/bar/", dir: "/foo", file: "bar"},
		{path: "/foo/bar/.", dir: "/foo/bar", file: "."},
		{path: "/foo/bar/./", dir: "/foo/bar", file: "."},
		{path: "/foo/bar/./.", dir: "/foo/bar/.", file: "."},
		{path: "/foo/bar/./..", dir: "/foo/bar/.", file: ".."},
		{path: "/foo/bar/..", dir: "/foo/bar", file: ".."},
		{path: "/foo/bar/../", dir: "/foo/bar", file: ".."},
		{path: "/foo/bar/../.", dir: "/foo/bar/..", file: "."},
		{path: "/foo/bar/../..", dir: "/foo/bar/..", file: ".."},

		{path: "foo", dir: ".", file: "foo"},
		{path: "foo", dir: ".", file: "foo"},
		{path: "foo/", dir: ".", file: "foo"},
		{path: "foo/.", dir: "foo", file: "."},
		{path: "foo/./", dir: "foo", file: "."},
		{path: "foo/./.", dir: "foo/.", file: "."},
		{path: "foo/./..", dir: "foo/.", file: ".."},
		{path: "foo/..", dir: "foo", file: ".."},
		{path: "foo/../", dir: "foo", file: ".."},
		{path: "foo/../.", dir: "foo/..", file: "."},
		{path: "foo/../..", dir: "foo/..", file: ".."},
		{path: "foo/", dir: ".", file: "foo"},
		{path: "foo/.", dir: "foo", file: "."},

		{path: "foo/bar", dir: "foo", file: "bar"},
		{path: "foo/bar/", dir: "foo", file: "bar"},
		{path: "foo/bar/.", dir: "foo/bar", file: "."},
		{path: "foo/bar/./", dir: "foo/bar", file: "."},
		{path: "foo/bar/./.", dir: "foo/bar/.", file: "."},
		{path: "foo/bar/./..", dir: "foo/bar/.", file: ".."},
		{path: "foo/bar/..", dir: "foo/bar", file: ".."},
		{path: "foo/bar/../", dir: "foo/bar", file: ".."},
		{path: "foo/bar/../.", dir: "foo/bar/..", file: "."},
		{path: "foo/bar/../..", dir: "foo/bar/..", file: ".."},
		{path: "foo/bar/", dir: "foo", file: "bar"},
		{path: "foo/bar/.", dir: "foo/bar", file: "."},
	}

	for _, c := range cases {
		dir, file := SplitLast(c.path)
		if dir != c.dir || file != c.file {
			t.Errorf("SplitLast(%q) got (%q, %q), expected (%q, %q)", c.path, dir, file, c.dir, c.file)
		}
	}
}

// TestSplitFirst tests variants of path splitting.
func TestSplitFirst(t *testing.T) {
	cases := []struct {
		path      string
		first     string
		remainder string
	}{
		{path: "/", first: "/", remainder: ""},
		{path: "/.", first: "/", remainder: "."},
		{path: "///.", first: "/", remainder: "//."},
		{path: "/.///", first: "/", remainder: "."},
		{path: "/./.", first: "/", remainder: "./."},
		{path: "/././", first: "/", remainder: "./."},
		{path: "/./..", first: "/", remainder: "./.."},
		{path: "/./../", first: "/", remainder: "./.."},
		{path: "/..", first: "/", remainder: ".."},
		{path: "/../", first: "/", remainder: ".."},
		{path: "/../.", first: "/", remainder: "../."},
		{path: "/.././", first: "/", remainder: "../."},
		{path: "/../..", first: "/", remainder: "../.."},
		{path: "/../../", first: "/", remainder: "../.."},

		{path: "", first: ".", remainder: ""},
		{path: ".", first: ".", remainder: ""},
		{path: "./", first: ".", remainder: ""},
		{path: ".///", first: ".", remainder: ""},
		{path: "./.", first: ".", remainder: "."},
		{path: "././", first: ".", remainder: "."},
		{path: "./..", first: ".", remainder: ".."},
		{path: "./../", first: ".", remainder: ".."},
		{path: "..", first: "..", remainder: ""},
		{path: "../", first: "..", remainder: ""},
		{path: "../.", first: "..", remainder: "."},
		{path: ".././", first: "..", remainder: "."},
		{path: "../..", first: "..", remainder: ".."},
		{path: "../../", first: "..", remainder: ".."},

		{path: "/foo", first: "/", remainder: "foo"},
		{path: "/foo/", first: "/", remainder: "foo"},
		{path: "/foo///", first: "/", remainder: "foo"},
		{path: "/foo/.", first: "/", remainder: "foo/."},
		{path: "/foo/./", first: "/", remainder: "foo/."},
		{path: "/foo/./.", first: "/", remainder: "foo/./."},
		{path: "/foo/./..", first: "/", remainder: "foo/./.."},
		{path: "/foo/..", first: "/", remainder: "foo/.."},
		{path: "/foo/../", first: "/", remainder: "foo/.."},
		{path: "/foo/../.", first: "/", remainder: "foo/../."},
		{path: "/foo/../..", first: "/", remainder: "foo/../.."},

		{path: "/foo/bar", first: "/", remainder: "foo/bar"},
		{path: "///foo/bar", first: "/", remainder: "//foo/bar"},
		{path: "/foo///bar", first: "/", remainder: "foo///bar"},
		{path: "/foo/bar/.", first: "/", remainder: "foo/bar/."},
		{path: "/foo/bar/./", first: "/", remainder: "foo/bar/."},
		{path: "/foo/bar/./.", first: "/", remainder: "foo/bar/./."},
		{path: "/foo/bar/./..", first: "/", remainder: "foo/bar/./.."},
		{path: "/foo/bar/..", first: "/", remainder: "foo/bar/.."},
		{path: "/foo/bar/../", first: "/", remainder: "foo/bar/.."},
		{path: "/foo/bar/../.", first: "/", remainder: "foo/bar/../."},
		{path: "/foo/bar/../..", first: "/", remainder: "foo/bar/../.."},

		{path: "foo", first: "foo", remainder: ""},
		{path: "foo", first: "foo", remainder: ""},
		{path: "foo/", first: "foo", remainder: ""},
		{path: "foo///", first: "foo", remainder: ""},
		{path: "foo/.", first: "foo", remainder: "."},
		{path: "foo/./", first: "foo", remainder: "."},
		{path: "foo/./.", first: "foo", remainder: "./."},
		{path: "foo/./..", first: "foo", remainder: "./.."},
		{path: "foo/..", first: "foo", remainder: ".."},
		{path: "foo/../", first: "foo", remainder: ".."},
		{path: "foo/../.", first: "foo", remainder: "../."},
		{path: "foo/../..", first: "foo", remainder: "../.."},
		{path: "foo/", first: "foo", remainder: ""},
		{path: "foo/.", first: "foo", remainder: "."},

		{path: "foo/bar", first: "foo", remainder: "bar"},
		{path: "foo///bar", first: "foo", remainder: "bar"},
		{path: "foo/bar/", first: "foo", remainder: "bar"},
		{path: "foo/bar/.", first: "foo", remainder: "bar/."},
		{path: "foo/bar/./", first: "foo", remainder: "bar/."},
		{path: "foo/bar/./.", first: "foo", remainder: "bar/./."},
		{path: "foo/bar/./..", first: "foo", remainder: "bar/./.."},
		{path: "foo/bar/..", first: "foo", remainder: "bar/.."},
		{path: "foo/bar/../", first: "foo", remainder: "bar/.."},
		{path: "foo/bar/../.", first: "foo", remainder: "bar/../."},
		{path: "foo/bar/../..", first: "foo", remainder: "bar/../.."},
		{path: "foo/bar/", first: "foo", remainder: "bar"},
		{path: "foo/bar/.", first: "foo", remainder: "bar/."},
	}

	for _, c := range cases {
		first, remainder := SplitFirst(c.path)
		if first != c.first || remainder != c.remainder {
			t.Errorf("SplitFirst(%q) got (%q, %q), expected (%q, %q)", c.path, first, remainder, c.first, c.remainder)
		}
	}
}
