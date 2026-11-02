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

package proc

import (
	"path"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/inet"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// sysDirAt returns the lazySysDir at path, without populating it.
func sysDirAt(t *testing.T, s *testutil.System, p string) *lazySysDir {
	t.Helper()
	vd := s.GetDentryOrDie(s.PathOpAtRoot(p))
	defer vd.DecRef(s.Ctx)
	d, ok := vd.Dentry().Impl().(*kernfs.Dentry).Inode().(*lazySysDir)
	if !ok {
		t.Fatalf("%s is not a lazySysDir", p)
	}
	return d
}

func TestSysDirPopulatedOnDemand(t *testing.T) {
	s := setupWithDataAndStack(t, &InternalData{}, inet.NewTestStack())
	defer s.Destroy()

	// Getting a dentry for /proc/sys/net/core only populates its ancestors.
	core := sysDirAt(t, s, "/proc/sys/net/core")
	if core.populated.Load() {
		t.Errorf("/proc/sys/net/core is populated before use")
	}
	if _, err := s.VFS.StatAt(s.Ctx, s.Creds, s.PathOpAtRoot("/proc/sys/net/core/somaxconn"), &vfs.StatOptions{}); err != nil {
		t.Fatalf("StatAt(/proc/sys/net/core/somaxconn): %v", err)
	}
	for _, tc := range []struct {
		path      string
		populated bool
	}{
		{"/proc/sys", true},
		{"/proc/sys/net", true},
		{"/proc/sys/net/core", true},
		{"/proc/sys/net/ipv4", false},
		{"/proc/sys/kernel", false},
	} {
		if got := sysDirAt(t, s, tc.path).populated.Load(); got != tc.populated {
			t.Errorf("%s populated = %t, want %t", tc.path, got, tc.populated)
		}
	}
}

func TestSysDirRmdir(t *testing.T) {
	s := setupWithDataAndStack(t, &InternalData{}, inet.NewTestStack())
	defer s.Destroy()

	// rmdir must fail the same way whether the directory is populated or not.
	const p = "/proc/sys/kernel/random"
	var errs []error
	for _, populate := range []bool{false, true} {
		if populate {
			s.ListDirents(s.PathOpAtRoot(p))
		}
		if got := sysDirAt(t, s, p).populated.Load(); got != populate {
			t.Fatalf("%s populated = %t, want %t", p, got, populate)
		}
		err := s.VFS.RmdirAt(s.Ctx, s.Creds, s.PathOpAtRoot(p))
		if err == nil {
			t.Fatalf("RmdirAt(%s) with populated = %t succeeded", p, populate)
		}
		errs = append(errs, err)
	}
	if errs[0] != errs[1] {
		t.Errorf("RmdirAt(%s): got error %v before populating, %v after", p, errs[0], errs[1])
	}
	if !linuxerr.Equals(linuxerr.ENOTEMPTY, errs[1]) {
		t.Errorf("RmdirAt(%s): got error %v, want ENOTEMPTY", p, errs[1])
	}
}

// TestSysDirMkdir checks that mkdir in a /proc/sys directory fails the same
// way whether the directory is populated or not. procfs looks up the name
// before it creates an entry (see kernfs.Filesystem.NoNegativeDentries), so
// mkdir must return EEXIST for a child that is not created yet.
func TestSysDirMkdir(t *testing.T) {
	s := setupWithDataAndStack(t, &InternalData{}, inet.NewTestStack())
	defer s.Destroy()

	for _, tc := range []struct {
		dir  string
		name string
		want error
	}{
		{dir: "/proc/sys/kernel/random", name: "boot_id", want: linuxerr.EEXIST},
		{dir: "/proc/sys/kernel/yama", name: "nonexistent", want: linuxerr.ENOENT},
	} {
		p := path.Join(tc.dir, tc.name)
		for _, populated := range []bool{false, true} {
			if got := sysDirAt(t, s, tc.dir).populated.Load(); got != populated {
				t.Fatalf("%s populated = %t, want %t", tc.dir, got, populated)
			}
			if err := s.VFS.MkdirAt(s.Ctx, s.Creds, s.PathOpAtRoot(p), &vfs.MkdirOptions{Mode: 0755}); err != tc.want {
				t.Errorf("MkdirAt(%s) with populated = %t: got error %v, want %v", p, populated, err, tc.want)
			}
		}
	}
}

// TestSysDirTree checks that every directory in /proc/sys has the right link
// count, and that lazySysDirs are never empty (see lazySysDir.HasChildren).
func TestSysDirTree(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stack inet.Stack
	}{
		{name: "stack", stack: inet.NewTestStack()},
		{name: "no stack"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := setupWithDataAndStack(t, &InternalData{}, tc.stack)
			defer s.Destroy()

			var walk func(p string)
			walk = func(p string) {
				// Open populates the directory, so check HasChildren first.
				vd := s.GetDentryOrDie(s.PathOpAtRoot(p))
				inode := vd.Dentry().Impl().(*kernfs.Dentry).Inode()
				vd.DecRef(s.Ctx)
				lazy, isLazy := inode.(*lazySysDir)
				if isLazy && !inode.HasChildren() {
					t.Errorf("unpopulated lazySysDir %s has no children", p)
				}

				dirents := s.ListDirents(s.PathOpAtRoot(p)).Dirents()
				if isLazy && !lazy.populated.Load() {
					t.Errorf("%s is not populated after getdents", p)
				}
				if isLazy && len(dirents) <= 2 {
					t.Errorf("lazySysDir %s is empty", p)
				}
				subdirs := 0
				for _, d := range dirents {
					if d.Name == "." || d.Name == ".." || d.Type != linux.DT_DIR {
						continue
					}
					subdirs++
					walk(path.Join(p, d.Name))
				}
				stat, err := s.VFS.StatAt(s.Ctx, s.Creds, s.PathOpAtRoot(p), &vfs.StatOptions{Mask: linux.STATX_NLINK})
				if err != nil {
					t.Fatalf("StatAt(%s): %v", p, err)
				}
				if want := uint32(2 + subdirs); stat.Nlink != want {
					t.Errorf("%s has link count %d, want %d", p, stat.Nlink, want)
				}
			}
			walk("/proc/sys")
		})
	}
}

// TestSysDirLinkCountBeforePopulate checks that stat on an unpopulated
// directory reports the link count of the populated directory without
// populating it.
func TestSysDirLinkCountBeforePopulate(t *testing.T) {
	s := setupWithDataAndStack(t, &InternalData{}, inet.NewTestStack())
	defer s.Destroy()

	const p = "/proc/sys/net/ipv6"
	if sysDirAt(t, s, p).populated.Load() {
		t.Fatalf("%s is populated before use", p)
	}
	stat, err := s.VFS.StatAt(s.Ctx, s.Creds, s.PathOpAtRoot(p), &vfs.StatOptions{Mask: linux.STATX_NLINK})
	if err != nil {
		t.Fatalf("StatAt(%s): %v", p, err)
	}
	// ipv6 has a single subdirectory, conf.
	if stat.Nlink != 3 {
		t.Errorf("%s has link count %d, want 3", p, stat.Nlink)
	}
	if sysDirAt(t, s, p).populated.Load() {
		t.Errorf("StatAt(%s) populated the directory", p)
	}
}
