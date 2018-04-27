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

package ramfs

import (
	"testing"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context/contexttest"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
)

func TestMakeDirectoryTree(t *testing.T) {
	mount := fs.NewNonCachingMountSource(nil, fs.MountSourceFlags{})

	for _, test := range []struct {
		name    string
		subdirs []string
	}{
		{
			name: "abs paths",
			subdirs: []string{
				"/tmp",
				"/tmp/a/b",
				"/tmp/a/c/d",
				"/tmp/c",
				"/proc",
				"/dev/a/b",
				"/tmp",
			},
		},
		{
			name: "rel paths",
			subdirs: []string{
				"tmp",
				"tmp/a/b",
				"tmp/a/c/d",
				"tmp/c",
				"proc",
				"dev/a/b",
				"tmp",
			},
		},
	} {
		ctx := contexttest.Context(t)
		tree, err := MakeDirectoryTree(ctx, mount, test.subdirs)
		if err != nil {
			t.Errorf("%s: failed to make ramfs tree, got error %v, want nil", test.name, err)
			continue
		}

		// Expect to be able to find each of the paths.
		mm, err := fs.NewMountNamespace(ctx, tree)
		if err != nil {
			t.Errorf("%s: failed to create mount manager: %v", test.name, err)
			continue
		}
		root := mm.Root()
		defer mm.DecRef()

		for _, p := range test.subdirs {
			if _, err := mm.FindInode(ctx, root, nil, p, 0); err != nil {
				t.Errorf("%s: failed to find node %s: %v", test.name, p, err)
				break
			}
		}
	}
}
