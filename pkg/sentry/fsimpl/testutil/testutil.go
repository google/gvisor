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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/usermem"

	"gvisor.dev/gvisor/pkg/hostarch"
)

// System represents the context for a single test.
//
// Test systems must be explicitly destroyed with System.Destroy.
type System struct {
	t     *testing.T
	Ctx   context.Context
	Creds *auth.Credentials
	VFS   *vfs.VirtualFilesystem
	Root  vfs.VirtualDentry
	MntNs *vfs.MountNamespace
}

// NewSystem constructs a System.
//
// Precondition: Caller must hold a reference on mns, whose ownership
// is transferred to the new System.
func NewSystem(ctx context.Context, t *testing.T, v *vfs.VirtualFilesystem, mns *vfs.MountNamespace) *System {
	root := mns.Root()
	root.IncRef()
	s := &System{
		t:     t,
		Ctx:   ctx,
		Creds: auth.CredentialsFromContext(ctx),
		VFS:   v,
		MntNs: mns,
		Root:  root,
	}
	return s
}

// WithSubtest creates a temporary test system with a new test harness,
// referencing all other resources from the original system. This is useful when
// a system is reused for multiple subtests, and the T needs to change for each
// case. Note that this is safe when test cases run in parallel, as all
// resources referenced by the system are immutable, or handle interior
// mutations in a thread-safe manner.
//
// The returned system must not outlive the original and should not be destroyed
// via System.Destroy.
func (s *System) WithSubtest(t *testing.T) *System {
	return &System{
		t:     t,
		Ctx:   s.Ctx,
		Creds: s.Creds,
		VFS:   s.VFS,
		MntNs: s.MntNs,
		Root:  s.Root,
	}
}

// WithTemporaryContext constructs a temporary test system with a new context
// ctx. The temporary system borrows all resources and references from the
// original system. The returned temporary system must not outlive the original
// system, and should not be destroyed via System.Destroy.
func (s *System) WithTemporaryContext(ctx context.Context) *System {
	return &System{
		t:     s.t,
		Ctx:   ctx,
		Creds: s.Creds,
		VFS:   s.VFS,
		MntNs: s.MntNs,
		Root:  s.Root,
	}
}

// Destroy release resources associated with a test system.
func (s *System) Destroy() {
	s.Root.DecRef(s.Ctx)
	s.MntNs.DecRef(s.Ctx) // Reference on MntNs passed to NewSystem.
}

// ReadToEnd reads the contents of fd until EOF to a string.
func (s *System) ReadToEnd(fd *vfs.FileDescription) (string, error) {
	buf := make([]byte, hostarch.PageSize)
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
func (s *System) PathOpAtRoot(path string) *vfs.PathOperation {
	return &vfs.PathOperation{
		Root:  s.Root,
		Start: s.Root,
		Path:  fspath.Parse(path),
	}
}

// GetDentryOrDie attempts to resolve a dentry referred to by the
// provided path operation. If unsuccessful, the test fails.
func (s *System) GetDentryOrDie(pop *vfs.PathOperation) vfs.VirtualDentry {
	vd, err := s.VFS.GetDentryAt(s.Ctx, s.Creds, pop, &vfs.GetDentryOptions{})
	if err != nil {
		s.t.Fatalf("GetDentryAt(pop:%+v) failed: %v", pop, err)
	}
	return vd
}

// DirentType is an alias for values for linux_dirent64.d_type.
type DirentType = uint8

// ListDirents lists the Dirents for a directory at pop.
func (s *System) ListDirents(pop *vfs.PathOperation) *DirentCollector {
	fd, err := s.VFS.OpenAt(s.Ctx, s.Creds, pop, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		s.t.Fatalf("OpenAt for PathOperation %+v failed: %v", pop, err)
	}
	defer fd.DecRef(s.Ctx)

	collector := &DirentCollector{}
	if err := fd.IterDirents(s.Ctx, collector); err != nil {
		s.t.Fatalf("IterDirent failed: %v", err)
	}
	return collector
}

// AssertAllDirentTypes verifies that the set of dirents in collector contains
// exactly the specified set of expected entries. AssertAllDirentTypes respects
// collector.skipDots, and implicitly checks for "." and ".." accordingly.
func (s *System) AssertAllDirentTypes(collector *DirentCollector, expected map[string]DirentType) {
	if expected == nil {
		expected = make(map[string]DirentType)
	}
	// Also implicitly check for "." and "..", if enabled.
	if !collector.skipDots {
		expected["."] = linux.DT_DIR
		expected[".."] = linux.DT_DIR
	}

	dentryTypes := make(map[string]DirentType)
	collector.mu.Lock()
	for _, dirent := range collector.dirents {
		dentryTypes[dirent.Name] = dirent.Type
	}
	collector.mu.Unlock()
	if diff := cmp.Diff(expected, dentryTypes); diff != "" {
		s.t.Fatalf("IterDirent had unexpected results:\n--- want\n+++ got\n%v", diff)
	}
}

// AssertDirentOffsets verifies that collector contains at least the entries
// specified in expected, with the given NextOff field. Entries specified in
// expected but missing from collector result in failure. Extra entries in
// collector are ignored. AssertDirentOffsets respects collector.skipDots, and
// implicitly checks for "." and ".." accordingly.
func (s *System) AssertDirentOffsets(collector *DirentCollector, expected map[string]int64) {
	// Also implicitly check for "." and "..", if enabled.
	if !collector.skipDots {
		expected["."] = 1
		expected[".."] = 2
	}

	dentryNextOffs := make(map[string]int64)
	collector.mu.Lock()
	for _, dirent := range collector.dirents {
		// Ignore extra entries in dentries that are not in expected.
		if _, ok := expected[dirent.Name]; ok {
			dentryNextOffs[dirent.Name] = dirent.NextOff
		}
	}
	collector.mu.Unlock()
	if diff := cmp.Diff(expected, dentryNextOffs); diff != "" {
		s.t.Fatalf("IterDirent had unexpected results:\n--- want\n+++ got\n%v", diff)
	}
}

// DirentCollector provides an implementation for vfs.IterDirentsCallback for
// testing. It simply iterates to the end of a given directory FD and collects
// all dirents emitted by the callback.
type DirentCollector struct {
	mu      sync.Mutex
	order   []*vfs.Dirent
	dirents map[string]*vfs.Dirent
	// When the collector is used in various Assert* functions, should "." and
	// ".." be implicitly checked?
	skipDots bool
}

// SkipDotsChecks enables or disables the implicit checks on "." and ".." when
// the collector is used in various Assert* functions. Note that "." and ".."
// are still collected if passed to d.Handle, so the caller should only disable
// the checks when they aren't expected.
func (d *DirentCollector) SkipDotsChecks(value bool) {
	d.skipDots = value
}

// Handle implements vfs.IterDirentsCallback.Handle.
func (d *DirentCollector) Handle(dirent vfs.Dirent) error {
	d.mu.Lock()
	if d.dirents == nil {
		d.dirents = make(map[string]*vfs.Dirent)
	}
	d.order = append(d.order, &dirent)
	d.dirents[dirent.Name] = &dirent
	d.mu.Unlock()
	return nil
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
		return fmt.Errorf("no dirent named %q found", name)
	}
	if dirent.Type != typ {
		return fmt.Errorf("dirent named %q found, but was expecting type %s, got: %+v", name, linux.DirentType.Parse(uint64(typ)), dirent)
	}
	return nil
}

// Dirents returns all dirents discovered by this collector.
func (d *DirentCollector) Dirents() map[string]*vfs.Dirent {
	d.mu.Lock()
	dirents := make(map[string]*vfs.Dirent)
	for n, d := range d.dirents {
		dirents[n] = d
	}
	d.mu.Unlock()
	return dirents
}

// OrderedDirents returns an ordered list of dirents as discovered by this
// collector.
func (d *DirentCollector) OrderedDirents() []*vfs.Dirent {
	d.mu.Lock()
	dirents := make([]*vfs.Dirent, len(d.order))
	copy(dirents, d.order)
	d.mu.Unlock()
	return dirents
}
