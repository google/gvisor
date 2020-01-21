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

// Package testutil provides common test utilities for kernfs-based
// filesystems.
package testutil

import (
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// System represents the context for a single test.
//
// Test systems must be explicitly destroyed with System.Destroy.
type System struct {
	t     *testing.T
	Ctx   context.Context
	Creds *auth.Credentials
	VFS   *vfs.VirtualFilesystem
	mns   *vfs.MountNamespace
	root  vfs.VirtualDentry
}

// NewSystem constructs a System.
//
// Precondition: Caller must hold a reference on mns, whose ownership
// is transferred to the new System.
func NewSystem(ctx context.Context, t *testing.T, v *vfs.VirtualFilesystem, mns *vfs.MountNamespace) *System {
	s := &System{
		t:     t,
		Ctx:   ctx,
		Creds: auth.CredentialsFromContext(ctx),
		VFS:   v,
		mns:   mns,
		root:  mns.Root(),
	}
	return s
}

// Destroy release resources associated with a test system.
func (s *System) Destroy() {
	s.root.DecRef()
	s.mns.DecRef(s.VFS) // Reference on mns passed to NewSystem.
}

// ReadToEnd reads the contents of fd until EOF to a string.
func (s *System) ReadToEnd(fd *vfs.FileDescription) (string, error) {
	buf := make([]byte, usermem.PageSize)
	bufIOSeq := usermem.BytesIOSequence(buf)
	opts := vfs.ReadOptions{}

	var content strings.Builder
	for {
		n, err := fd.Read(s.Ctx, bufIOSeq, opts)
		if n == 0 || err != nil {
			if err == io.EOF {
				err = nil
			}
			return content.String(), err
		}
		content.Write(buf[:n])
	}
}

// PathOpAtRoot constructs a PathOperation with the given path from
// the root of the filesystem.
func (s *System) PathOpAtRoot(path string) vfs.PathOperation {
	return vfs.PathOperation{
		Root:  s.root,
		Start: s.root,
		Path:  fspath.Parse(path),
	}
}

// GetDentryOrDie attempts to resolve a dentry referred to by the
// provided path operation. If unsuccessful, the test fails.
func (s *System) GetDentryOrDie(pop vfs.PathOperation) vfs.VirtualDentry {
	vd, err := s.VFS.GetDentryAt(s.Ctx, s.Creds, &pop, &vfs.GetDentryOptions{})
	if err != nil {
		s.t.Fatalf("GetDentryAt(pop:%+v) failed: %v", pop, err)
	}
	return vd
}

// DirentType is an alias for values for linux_dirent64.d_type.
type DirentType = uint8

// AssertDirectoryContains verifies that a directory at pop contains the entries
// specified. AssertDirectoryContains implicitly checks for "." and "..", these
// need not be included in entries.
func (s *System) AssertDirectoryContains(pop *vfs.PathOperation, entries map[string]DirentType) {
	// Also implicitly check for "." and "..".
	entries["."] = linux.DT_DIR
	entries[".."] = linux.DT_DIR

	fd, err := s.VFS.OpenAt(s.Ctx, s.Creds, pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		s.t.Fatalf("OpenAt for PathOperation %+v failed: %v", pop, err)
	}
	defer fd.DecRef()

	collector := &DirentCollector{}
	if err := fd.IterDirents(s.Ctx, collector); err != nil {
		s.t.Fatalf("IterDirent failed: %v", err)
	}

	collectedEntries := make(map[string]DirentType)
	for _, dirent := range collector.dirents {
		collectedEntries[dirent.Name] = dirent.Type
	}
	if diff := cmp.Diff(entries, collectedEntries); diff != "" {
		s.t.Fatalf("IterDirent had unexpected results:\n--- want\n+++ got\n%v", diff)
	}
}

// DirentCollector provides an implementation for vfs.IterDirentsCallback for
// testing. It simply iterates to the end of a given directory FD and collects
// all dirents emitted by the callback.
type DirentCollector struct {
	mu      sync.Mutex
	dirents map[string]vfs.Dirent
}

// Handle implements vfs.IterDirentsCallback.Handle.
func (d *DirentCollector) Handle(dirent vfs.Dirent) bool {
	d.mu.Lock()
	if d.dirents == nil {
		d.dirents = make(map[string]vfs.Dirent)
	}
	d.dirents[dirent.Name] = dirent
	d.mu.Unlock()
	return true
}

// Count returns the number of dirents currently in the collector.
func (d *DirentCollector) Count() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.dirents)
}

// Contains checks whether the collector has a dirent with the given name and
// type.
func (d *DirentCollector) Contains(name string, typ uint8) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	dirent, ok := d.dirents[name]
	if !ok {
		return fmt.Errorf("No dirent named %q found", name)
	}
	if dirent.Type != typ {
		return fmt.Errorf("Dirent named %q found, but was expecting type %s, got: %+v", name, linux.DirentType.Parse(uint64(typ)), dirent)
	}
	return nil
}
