package erofs

import (
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// We need to define an interface instead of using atomic.Pointer because
// the Dentry type gets removed during code generation and the compiler
// complains about the unused sync/atomic type.
type genericatomicptrDentry interface {
	Load() *dentry
	Store(*dentry)
}

// ParentOrSelf returns d.parent. If d.parent is nil, ParentOrSelf returns d.
func genericParentOrSelf(d *dentry) *dentry {
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
func genericSetParentAndName(fs *filesystem, d, newParent *dentry, newName string) {
	fs.ancestryMu.Lock()
	defer fs.ancestryMu.Unlock()
	d.parent.Store(newParent)
	d.name = newName
}

// IsAncestorDentry returns true if d is an ancestor of d2; that is, d is
// either d2's parent or an ancestor of d2's parent.
func genericIsAncestorDentry(fs *filesystem, d, d2 *dentry) bool {
	if d == d2 {
		return false
	}
	return genericIsDescendant(fs, &d.vfsd, d2)
}

// IsDescendant returns true if vd is a descendant of vfsroot or if vd and
// vfsroot are the same dentry.
func genericIsDescendant(fs *filesystem, vfsroot *vfs.Dentry, d *dentry) bool {
	fs.ancestryMu.RLock()
	defer fs.ancestryMu.RUnlock()
	for d != nil && &d.vfsd != vfsroot {
		d = d.parent.Load()
	}
	return d != nil
}

// PrependPath is a generic implementation of FilesystemImpl.PrependPath().
func genericPrependPath(fs *filesystem, vfsroot vfs.VirtualDentry, mnt *vfs.Mount, d *dentry, b *fspath.Builder) error {
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
func genericDebugPathname(fs *filesystem, d *dentry) string {
	var b fspath.Builder
	_ = genericPrependPath(fs, vfs.VirtualDentry{}, nil, d, &b)
	return b.String()
}
