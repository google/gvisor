// Copyright 2020 The gVisor Authors.
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

// Package genericfstree provides tools for implementing vfs.FilesystemImpls
// that follow a standard pattern for synchronizing Dentry parent and name.
//
// Clients using this package must use the go_template_instance rule in
// tools/go_generics/defs.bzl to create an instantiation of this template
// package, providing types to use in place of Filesystem and Dentry.
//
// TODO: As of this writing, every filesystem implementation with its own
// dentry type uses at least part of genericfstree, suggesting that we may want
// to merge its functionality into vfs.Dentry. However, this will incur the
// cost of an extra (entirely predictable) branch per directory traversal,
// since Dentry.parent will need to be atomic.Pointer[vfs.Dentry] rather than a
// filesystem-specific dentry, requiring a type assertion to the latter.
package genericfstree

import (
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// We need to define an interface instead of using atomic.Pointer because
// the Dentry type gets removed during code generation and the compiler
// complains about the unused sync/atomic type.
type atomicptrDentry interface {
	Load() *Dentry
	Store(*Dentry)
}

// Filesystem is a required type parameter that is a struct with the given
// fields.
type Filesystem struct {
	// ancestryMu makes parent and name writes atomic for all dentries in the
	// filesystem.
	ancestryMu sync.RWMutex
}

// Dentry is a required type parameter that is a struct with the given fields.
type Dentry struct {
	// vfsd is the embedded vfs.Dentry corresponding to this vfs.DentryImpl.
	vfsd vfs.Dentry

	// parent is the parent of this Dentry in the filesystem's tree. If this
	// Dentry is a filesystem root, parent is nil.
	parent atomicptrDentry

	// name is the name of this Dentry in its parent. If this Dentry is a
	// filesystem root, name is unspecified.
	name string
}

// ParentOrSelf returns d.parent. If d.parent is nil, ParentOrSelf returns d.
func ParentOrSelf(d *Dentry) *Dentry {
	if parent := d.parent.Load(); parent != nil {
		return parent
	}
	return d
}

// SetParentAndName atomically replaces a Dentry's parent and name.
//
// SetParentAndName must be used when changes to a Dentry's parent and name may
// race with observations of the same. If a Dentry is not visible to other
// goroutines (including concurrent calls to PrependPath or IsDescendant) when
// its parent and name are changed, it is safe to either call SetParentAndName
// or mutate d.parent and d.name directly.
func SetParentAndName(fs *Filesystem, d, newParent *Dentry, newName string) {
	fs.ancestryMu.Lock()
	defer fs.ancestryMu.Unlock()
	d.parent.Store(newParent)
	d.name = newName
}

// IsAncestorDentry returns true if d is an ancestor of d2; that is, d is
// either d2's parent or an ancestor of d2's parent.
func IsAncestorDentry(fs *Filesystem, d, d2 *Dentry) bool {
	if d == d2 {
		return false
	}
	return IsDescendant(fs, &d.vfsd, d2)
}

// IsDescendant returns true if vd is a descendant of vfsroot or if vd and
// vfsroot are the same dentry.
func IsDescendant(fs *Filesystem, vfsroot *vfs.Dentry, d *Dentry) bool {
	fs.ancestryMu.RLock()
	defer fs.ancestryMu.RUnlock()
	for d != nil && &d.vfsd != vfsroot {
		d = d.parent.Load()
	}
	return d != nil
}

// PrependPath is a generic implementation of FilesystemImpl.PrependPath().
func PrependPath(fs *Filesystem, vfsroot vfs.VirtualDentry, mnt *vfs.Mount, d *Dentry, b *fspath.Builder) error {
	fs.ancestryMu.RLock()
	defer fs.ancestryMu.RUnlock()
	for {
		if mnt == vfsroot.Mount() && &d.vfsd == vfsroot.Dentry() {
			return vfs.PrependPathAtVFSRootError{}
		}
		if mnt != nil && &d.vfsd == mnt.Root() {
			return nil
		}
		parent := d.parent.Load()
		if parent == nil {
			return vfs.PrependPathAtNonMountRootError{}
		}
		b.PrependComponent(d.name)
		d = parent
	}
}

// DebugPathname returns a pathname to d relative to its filesystem root.
// DebugPathname does not correspond to any Linux function; it's used to
// generate dentry pathnames for debugging.
func DebugPathname(fs *Filesystem, d *Dentry) string {
	var b fspath.Builder
	_ = PrependPath(fs, vfs.VirtualDentry{}, nil, d, &b)
	return b.String()
}
