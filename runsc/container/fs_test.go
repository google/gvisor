// Copyright 2018 Google LLC
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
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"testing"

	"gvisor.googlesource.com/gvisor/runsc/test/testutil"
)

type dir struct {
	rel  string
	link string
}

func construct(root string, dirs []dir) error {
	for _, d := range dirs {
		p := path.Join(root, d.rel)
		if d.link == "" {
			if err := os.MkdirAll(p, 0755); err != nil {
				return fmt.Errorf("error creating dir: %v", err)
			}
		} else {
			if err := os.MkdirAll(path.Dir(p), 0755); err != nil {
				return fmt.Errorf("error creating dir: %v", err)
			}
			if err := os.Symlink(d.link, p); err != nil {
				return fmt.Errorf("error creating symlink: %v", err)
			}
		}
	}
	return nil
}

func TestResolveSymlinks(t *testing.T) {
	root, err := ioutil.TempDir(testutil.TmpDir(), "root")
	if err != nil {
		t.Fatal("ioutil.TempDir() failed:", err)
	}
	dirs := []dir{
		{"dir1/dir11/dir111/dir1111", ""}, // Just a boring dir
		{"dir1/lnk12", "dir11"},           // Link to sibling
		{"dir1/lnk13", "./dir11"},         // Link to sibling through self
		{"dir1/lnk14", "../dir1/dir11"},   // Link to sibling through parent
		{"dir1/dir15/lnk151", ".."},       // Link to parent
		{"dir1/lnk16", "dir11/dir111"},    // Link to child
		{"dir1/lnk17", "."},               // Link to self
		{"dir1/lnk18", "lnk13"},           // Link to link
		{"lnk2", "dir1/lnk13"},            // Link to link to link
		{"dir3/dir21/lnk211", "../.."},    // Link to root relative
		{"dir3/lnk22", "/"},               // Link to root absolute
		{"dir3/lnk23", "/dir1"},           // Link to dir absolute
		{"dir3/lnk24", "/dir1/lnk12"},     // Link to link absolute
		{"lnk5", "../../.."},              // Link outside root
	}
	if err := construct(root, dirs); err != nil {
		t.Fatal("construct failed:", err)
	}

	tests := []struct {
		name        string
		rel         string
		want        string
		compareHost bool
	}{
		{name: "root", rel: "/", want: "/", compareHost: true},
		{name: "basic dir", rel: "/dir1/dir11/dir111", want: "/dir1/dir11/dir111", compareHost: true},
		{name: "dot 1", rel: "/dir1/dir11/./dir111", want: "/dir1/dir11/dir111", compareHost: true},
		{name: "dot 2", rel: "/dir1/././dir11/./././././dir111/.", want: "/dir1/dir11/dir111", compareHost: true},
		{name: "dotdot 1", rel: "/dir1/dir11/../dir15", want: "/dir1/dir15", compareHost: true},
		{name: "dotdot 2", rel: "/dir1/dir11/dir1111/../..", want: "/dir1", compareHost: true},

		{name: "link sibling", rel: "/dir1/lnk12", want: "/dir1/dir11", compareHost: true},
		{name: "link sibling + dir", rel: "/dir1/lnk12/dir111", want: "/dir1/dir11/dir111", compareHost: true},
		{name: "link sibling through self", rel: "/dir1/lnk13", want: "/dir1/dir11", compareHost: true},
		{name: "link sibling through parent", rel: "/dir1/lnk14", want: "/dir1/dir11", compareHost: true},

		{name: "link parent", rel: "/dir1/dir15/lnk151", want: "/dir1", compareHost: true},
		{name: "link parent + dir", rel: "/dir1/dir15/lnk151/dir11", want: "/dir1/dir11", compareHost: true},
		{name: "link child", rel: "/dir1/lnk16", want: "/dir1/dir11/dir111", compareHost: true},
		{name: "link child + dir", rel: "/dir1/lnk16/dir1111", want: "/dir1/dir11/dir111/dir1111", compareHost: true},
		{name: "link self", rel: "/dir1/lnk17", want: "/dir1", compareHost: true},
		{name: "link self + dir", rel: "/dir1/lnk17/dir11", want: "/dir1/dir11", compareHost: true},

		{name: "link^2", rel: "/dir1/lnk18", want: "/dir1/dir11", compareHost: true},
		{name: "link^2 + dir", rel: "/dir1/lnk18/dir111", want: "/dir1/dir11/dir111", compareHost: true},
		{name: "link^3", rel: "/lnk2", want: "/dir1/dir11", compareHost: true},
		{name: "link^3 + dir", rel: "/lnk2/dir111", want: "/dir1/dir11/dir111", compareHost: true},

		{name: "link abs", rel: "/dir3/lnk23", want: "/dir1"},
		{name: "link abs + dir", rel: "/dir3/lnk23/dir11", want: "/dir1/dir11"},
		{name: "link^2 abs", rel: "/dir3/lnk24", want: "/dir1/dir11"},
		{name: "link^2 abs + dir", rel: "/dir3/lnk24/dir111", want: "/dir1/dir11/dir111"},

		{name: "root link rel", rel: "/dir3/dir21/lnk211", want: "/", compareHost: true},
		{name: "root link abs", rel: "/dir3/lnk22", want: "/"},
		{name: "root contain link", rel: "/lnk5/dir1", want: "/dir1"},
		{name: "root contain dotdot", rel: "/dir1/dir11/../../../../../../../..", want: "/"},

		{name: "crazy", rel: "/dir3/dir21/lnk211/dir3/lnk22/dir1/dir11/../../lnk5/dir3/../dir3/lnk24/dir111/dir1111/..", want: "/dir1/dir11/dir111"},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got, err := resolveSymlinks(root, tst.rel)
			if err != nil {
				t.Errorf("resolveSymlinks(root, %q) failed: %v", tst.rel, err)
			}
			want := path.Join(root, tst.want)
			if got != want {
				t.Errorf("resolveSymlinks(root, %q) got: %q, want: %q", tst.rel, got, want)
			}
			if tst.compareHost {
				// Check that host got to the same end result.
				host, err := filepath.EvalSymlinks(path.Join(root, tst.rel))
				if err != nil {
					t.Errorf("path.EvalSymlinks(root, %q) failed: %v", tst.rel, err)
				}
				if host != got {
					t.Errorf("resolveSymlinks(root, %q) got: %q, want: %q", tst.rel, host, got)
				}
			}
		})
	}
}

func TestResolveSymlinksLoop(t *testing.T) {
	root, err := ioutil.TempDir(testutil.TmpDir(), "root")
	if err != nil {
		t.Fatal("ioutil.TempDir() failed:", err)
	}
	dirs := []dir{
		{"loop1", "loop2"},
		{"loop2", "loop1"},
	}
	if err := construct(root, dirs); err != nil {
		t.Fatal("construct failed:", err)
	}
	if _, err := resolveSymlinks(root, "loop1"); err == nil {
		t.Errorf("resolveSymlinks() should have failed")
	}
}
