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

package proc

import (
	"fmt"
	"strconv"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/syserror"
)

// file should be implemented by all file implementations which can be used
// to get a file description representing that file. All file implementations
// must have dentry as their first field by value and are reponsible for
// calling dentry.init().
type file interface {
	// open constructs a file description for this file.
	open(mount *vfs.Mount, flags uint32) *vfs.FileDescription
}

// dentry implements vfs.DentryImpl. There are no hard links within procfs so
// there is no need to differentiate between a dentry and inode. The "." and
// ".." hard link entries are handled in vfs.ResolvingPath.ResolveComponent().
type dentry struct {
	vfsd vfs.Dentry

	// refs is a reference count. refs is accessed using atomic memory
	// operations.
	//
	// A reference is held on all inodes that are reachable in the filesystem
	// tree. For non-directories (which may have multiple hard links), this
	// means that a reference is dropped when nlink reaches 0. For directories,
	// nlink never reaches 0 due to the "." entry; instead,
	// filesystem.RmdirAt() drops the reference.
	refs int64

	// Inode metadata. Immutable.
	permissions uint16 // Part of file mode.
	nlink       uint32 // 1 for regular files and 2 for directories.
	uid         auth.KUID
	gid         auth.KGID
	ino         uint64

	impl file // immutable

	// dentryEntry links dentries into their parent directory.childList.
	dentryEntry

	// isDirIterator is used to represent fake dirents which mark the position of
	// directoryFDs directory.childList.
	isDirIterator bool
}

// init must be called at construction of the dentry. No constructor is
// provided because dentry is meant to be used by value in files.
func (d *dentry) init(impl file, fs *filesystem, uid auth.KUID, gid auth.KGID, permissions uint16, nlink uint32) {
	d.vfsd.Init(d)
	d.refs = 1 // Initialize to 1 because this is being added to the dentry tree.
	d.impl = impl
	d.uid = uid
	d.gid = gid
	d.permissions = permissions
	d.nlink = nlink
	d.ino = atomic.AddUint64(&fs.nextInoMinusOne, 1)
}

// IncRef implements vfs.DentryImpl.IncRef.
func (d *dentry) IncRef(vfsfs *vfs.Filesystem) {
	if atomic.AddInt64(&d.refs, 1) <= 1 {
		panic("memfs.inode.incRef() called without holding a reference")
	}
}

// TryIncRef implements vfs.DentryImpl.TryIncRef.
func (d *dentry) TryIncRef(vfsfs *vfs.Filesystem) bool {
	for {
		refs := atomic.LoadInt64(&d.refs)
		if refs == 0 {
			return false
		}
		if atomic.CompareAndSwapInt64(&d.refs, refs, refs+1) {
			return true
		}
	}
}

// DecRef implements vfs.DentryImpl.DecRef.
func (d *dentry) DecRef(vfsfs *vfs.Filesystem) {
	if refs := atomic.AddInt64(&d.refs, -1); refs == 0 {
		d.release()
	} else if refs < 0 {
		panic("memfs.inode.decRef() called without holding a reference")
	}
}

// release is called when the ref count of the dentry hits 0.
func (d *dentry) release() {
	// TODO(b/138862512): This will mostly be noop for most implementations.
	// But some implementations might require cleanup. For example, /proc/TID/fd/
	// implementation will hold a reference on the file descriptor it represents
	// which will need to be decref'd once the dentry ref count hits 0.
}

func (d *dentry) statTo(stat *linux.Statx) {
	stat.Mask = linux.STATX_BLOCKS | linux.STATX_GID | linux.STATX_INO | linux.STATX_MODE |
		linux.STATX_NLINK | linux.STATX_SIZE | linux.STATX_TYPE | linux.STATX_UID
	stat.Blksize = 1024 // as defined in fs/proc/inode.c:proc_fill_super().
	stat.Nlink = d.nlink
	stat.UID = uint32(d.uid)
	stat.GID = uint32(d.gid)
	stat.Mode = uint16(d.permissions)
	stat.Ino = d.ino
	stat.Size = 0   // does not occupy any space on disk as its a virtual fs.
	stat.Blocks = 0 // ...

	// TODO(b/138862512): Add filetype to mode based on implementation.
}

func (d *dentry) fileType() uint8 {
	switch d.impl.(type) {
	case *staticFile, *dynamicFile:
		return linux.DT_REG
	case *directory:
		return linux.DT_DIR
	case *symlink:
		return linux.DT_LNK
	default:
		panic(fmt.Sprintf("unknown inode type: %T", d.impl))
	}
}

// staticFile can be used to represent a read-only regular files whose contents
// are static.
type staticFile struct {
	dentry dentry

	data []byte
}

var _ file = (*staticFile)(nil)

// newStaticFile is the staticFile constructor.
func (fs *filesystem) newStaticFile(data []byte, uid auth.KUID, gid auth.KGID, permissions uint16) *staticFile {
	f := &staticFile{data: data}
	f.dentry.init(f, fs, uid, gid, permissions, 1)
	return f
}

func (d *dentry) isStatic() bool {
	_, ok := d.impl.(*staticFile)
	return ok
}

// dynamicFile can be used to represent a read-only regular files whose contents
// are backed by vfs.DynamicBytesSource.
type dynamicFile struct {
	dentry dentry

	dataSource vfs.DynamicBytesSource
}

var _ file = (*dynamicFile)(nil)

// newDynamicFile is the dynamicFile constructor.
func (fs *filesystem) newDynamicFile(src vfs.DynamicBytesSource, uid auth.KUID, gid auth.KGID, permissions uint16) *dynamicFile {
	f := &dynamicFile{dataSource: src}
	f.dentry.init(f, fs, uid, gid, permissions, 1)
	return f
}

func (d *dentry) isDynamic() bool {
	_, ok := d.impl.(*dynamicFile)
	return ok
}

// directory represents a generic procfs directory.
type directory struct {
	dentry dentry

	// childList is a list containing (1) child Dentries and (2) fake Dentries
	// (with inode == nil) that represent the iteration position of
	// directoryFDs. childList is used to support directoryFD.IterDirents()
	// efficiently. childList is protected by filesystem.mu.
	childList dentryList
}

var _ file = (*directory)(nil)

// newDirectory is the directory constructor.
func (fs *filesystem) newDirectory(uid auth.KUID, gid auth.KGID, permissions uint16) *directory {
	dir := &directory{}
	dir.dentry.init(dir, fs, uid, gid, permissions, 2)
	return dir
}

func (d *dentry) isDir() bool {
	_, ok := d.impl.(*directory)
	return ok
}

// symlink represents a generic procfs symlink.
// The following procfs entries are symbolic links (according to proc(5)):
//   - /proc/self -> process's own /proc/[pid] directory
//   - /proc/thread-self -> process's own /proc/self/task/[tid] directory
//   - /proc/[pid]/cwd -> current working directory of the process
//   - /proc/[pid]/exe -> actual pathname of the executed command
//   - /proc/[pid]/fd/[fd no] -> actual file
//   - /proc/[pid]/map_files/[addr] -> mapped file themselves
//   - /proc/[pid]/root -> process's root directory
//
// /proc/self and /proc/thread-self are magical links as they are resolved
// based on the calling task.
type symlink struct {
	dentry   dentry
	resolver symlinkResolver
}

var _ file = (*symlink)(nil)

// symlinkResolver can be used to abstract the complexity of having different
// kinds of symlinks: static, dynamic or magical.
type symlinkResolver interface {
	readlink(ctx context.Context, s *symlink) (string, error)
}

// newSymlink is the symlink constructor.
func (fs *filesystem) newSymlink(resolver symlinkResolver, uid auth.KUID, gid auth.KGID, permissions uint16) *symlink {
	f := &symlink{resolver: resolver}
	f.dentry.init(f, fs, uid, gid, permissions, 1)
	return f
}

func (d *dentry) isSymlink() bool {
	_, ok := d.impl.(*symlink)
	return ok
}

// symlinkResolver implementations.

// self the magical symlink which represents /proc/self.
type self struct {
	pidns *kernel.PIDNamespace
}

// readlink implements symlinkResolver.readlink.
func (s *self) readlink(ctx context.Context, _ *symlink) (string, error) {
	if t := kernel.TaskFromContext(ctx); t != nil {
		tgid := s.pidns.IDOfThreadGroup(t.ThreadGroup())
		if tgid == 0 {
			return "", syserror.ENOENT
		}
		return strconv.FormatUint(uint64(tgid), 10), nil
	}

	// Who is reading this link?
	return "", syserror.EINVAL
}

// threadSelf the magical symlink which represents /proc/thread-self.
type threadSelf struct {
	pidns *kernel.PIDNamespace
}

// readlink implements symlinkResolver.readlink.
func (s *threadSelf) readlink(ctx context.Context, _ *symlink) (string, error) {
	if t := kernel.TaskFromContext(ctx); t != nil {
		tgid := s.pidns.IDOfThreadGroup(t.ThreadGroup())
		tid := s.pidns.IDOfTask(t)
		if tid == 0 || tgid == 0 {
			return "", syserror.ENOENT
		}
		return fmt.Sprintf("%d/task/%d", tgid, tid), nil
	}

	// Who is reading this link?
	return "", syserror.EINVAL
}
