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
// where a single statically-determined lock or set of locks is sufficient to
// ensure that a Dentry's name and parent are contextually immutable.
//
// Clients using this package must use the go_template_instance rule in
// tools/go_generics/defs.bzl to create an instantiation of this template
// package, providing types to use in place of Dentry.
package genericfstree

import (
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// We need to define an interface instead of using atomic.Pointer because
// the Dentry type gets removed during code generation and the compiler
// complains about the unused sync/atomic type.
type atomicptr interface {
	Load() *Dentry
}

// Dentry is a required type parameter that is a struct with the given fields.
//
// +stateify savable
type Dentry struct {
	// vfsd is the embedded vfs.Dentry corresponding to this vfs.DentryImpl.
	vfsd vfs.Dentry

	// parent is the parent of this Dentry in the filesystem's tree. If this
	// Dentry is a filesystem root, parent is nil.
	parent atomicptr

	// name is the name of this Dentry in its parent. If this Dentry is a
	// filesystem root, name is unspecified.
	name string
}

// IsAncestorDentry returns true if d is an ancestor of d2; that is, d is
// either d2's parent or an ancestor of d2's parent.
func IsAncestorDentry(d, d2 *Dentry) bool {
	for d2 != nil { // Stop at root, where d2.parent == nil.
		parent := d2.parent.Load()
		if parent == d {
			return true
		}
		if parent == d2 {
			return false
		}
		d2 = parent
	}
	return false
}

// IsDescendant returns true if vd is a descendant of vfsroot or if vd and
// vfsroot are the same dentry.
func IsDescendant(vfsroot *vfs.Dentry, d *Dentry) bool {
	for d != nil && &d.vfsd != vfsroot {
		d = d.parent.Load()
	}
	return d != nil
}

// ParentOrSelf returns d.parent. If d.parent is nil, ParentOrSelf returns d.
func ParentOrSelf(d *Dentry) *Dentry {
	if parent := d.parent.Load(); parent != nil {
		return parent
	}
	return d
}

// PrependPath is a generic implementation of FilesystemImpl.PrependPath().
func PrependPath(vfsroot vfs.VirtualDentry, mnt *vfs.Mount, d *Dentry, b *fspath.Builder) error {
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
func DebugPathname(d *Dentry) string {
	var b fspath.Builder
	_ = PrependPath(vfs.VirtualDentry{}, nil, d, &b)
	return b.String()
}
