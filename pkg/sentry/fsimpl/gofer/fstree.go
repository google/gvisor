package gofer

import (
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// IsAncestorDentry returns true if d is an ancestor of d2; that is, d is
// either d2's parent or an ancestor of d2's parent.
func genericIsAncestorDentry(d, d2 *dentry) bool {
	for d2 != nil {
		if d2.parent == d {
			return true
		}
		if d2.parent == d2 {
			return false
		}
		d2 = d2.parent
	}
	return false
}

// ParentOrSelf returns d.parent. If d.parent is nil, ParentOrSelf returns d.
func genericParentOrSelf(d *dentry) *dentry {
	if d.parent != nil {
		return d.parent
	}
	return d
}

// PrependPath is a generic implementation of FilesystemImpl.PrependPath().
func genericPrependPath(vfsroot vfs.VirtualDentry, mnt *vfs.Mount, d *dentry, b *fspath.Builder) error {
	for {
		if mnt == vfsroot.Mount() && &d.vfsd == vfsroot.Dentry() {
			return vfs.PrependPathAtVFSRootError{}
		}
		if &d.vfsd == mnt.Root() {
			return nil
		}
		if d.parent == nil {
			return vfs.PrependPathAtNonMountRootError{}
		}
		b.PrependComponent(d.name)
		d = d.parent
	}
}
