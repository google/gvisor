package kernfs

import (
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// We need to define an interface instead of using atomic.Pointer because
// the Dentry type gets removed during code generation and the compiler
// complains about the unused sync/atomic type.
type genericatomicptr interface {
	Load() *Dentry
}

// IsAncestorDentry returns true if d is an ancestor of d2; that is, d is
// either d2's parent or an ancestor of d2's parent.
func genericIsAncestorDentry(d, d2 *Dentry) bool {
	for d2 != nil {
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
func genericIsDescendant(vfsroot *vfs.Dentry, d *Dentry) bool {
	for d != nil && &d.vfsd != vfsroot {
		d = d.parent.Load()
	}
	return d != nil
}

// ParentOrSelf returns d.parent. If d.parent is nil, ParentOrSelf returns d.
func genericParentOrSelf(d *Dentry) *Dentry {
	if parent := d.parent.Load(); parent != nil {
		return parent
	}
	return d
}

// PrependPath is a generic implementation of FilesystemImpl.PrependPath().
func genericPrependPath(vfsroot vfs.VirtualDentry, mnt *vfs.Mount, d *Dentry, b *fspath.Builder) error {
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
func genericDebugPathname(d *Dentry) string {
	var b fspath.Builder
	_ = genericPrependPath(vfs.VirtualDentry{}, nil, d, &b)
	return b.String()
}
