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

// Package host provides a filesystem implementation for host files imported as
// file descriptors.
package host

import (
	"fmt"
	"math"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	unixsocket "gvisor.dev/gvisor/pkg/sentry/socket/unix"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// inode implements kernfs.Inode.
//
// +stateify savable
type inode struct {
	kernfs.InodeNoStatFS
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink
	kernfs.CachedMappable
	kernfs.InodeTemporary // This holds no meaning as this inode can't be Looked up and is always valid.

	locks vfs.FileLocks

	// When the reference count reaches zero, the host fd is closed.
	inodeRefs

	// hostFD contains the host fd that this file was originally created from,
	// which must be available at time of restore.
	//
	// This field is initialized at creation time and is immutable.
	hostFD int

	// ino is an inode number unique within this filesystem.
	//
	// This field is initialized at creation time and is immutable.
	ino uint64

	// ftype is the file's type (a linux.S_IFMT mask).
	//
	// This field is initialized at creation time and is immutable.
	ftype uint16

	// mayBlock is true if hostFD is non-blocking, and operations on it may
	// return EAGAIN or EWOULDBLOCK instead of blocking.
	//
	// This field is initialized at creation time and is immutable.
	mayBlock bool

	// seekable is false if lseek(hostFD) returns ESPIPE. We assume that file
	// offsets are meaningful iff seekable is true.
	//
	// This field is initialized at creation time and is immutable.
	seekable bool

	// isTTY is true if this file represents a TTY.
	//
	// This field is initialized at creation time and is immutable.
	isTTY bool

	// savable is true if hostFD may be saved/restored by its numeric value.
	//
	// This field is initialized at creation time and is immutable.
	savable bool

	// Event queue for blocking operations.
	queue waiter.Queue

	// If haveBuf is non-zero, hostFD represents a pipe, and buf contains data
	// read from the pipe from previous calls to inode.beforeSave(). haveBuf
	// and buf are protected by bufMu. haveBuf is accessed using atomic memory
	// operations.
	bufMu   sync.Mutex `state:"nosave"`
	haveBuf uint32
	buf     []byte
}

func newInode(ctx context.Context, fs *filesystem, hostFD int, savable bool, fileType linux.FileMode, isTTY bool) (*inode, error) {
	// Determine if hostFD is seekable.
	_, err := unix.Seek(hostFD, 0, linux.SEEK_CUR)
	seekable := !linuxerr.Equals(linuxerr.ESPIPE, err)
	// We expect regular files to be seekable, as this is required for them to
	// be memory-mappable.
	if !seekable && fileType == unix.S_IFREG {
		ctx.Infof("host.newInode: host FD %d is a non-seekable regular file", hostFD)
		return nil, syserror.ESPIPE
	}

	i := &inode{
		hostFD:   hostFD,
		ino:      fs.NextIno(),
		ftype:    uint16(fileType),
		mayBlock: fileType != unix.S_IFREG && fileType != unix.S_IFDIR,
		seekable: seekable,
		isTTY:    isTTY,
		savable:  savable,
	}
	i.InitRefs()
	i.CachedMappable.Init(hostFD)

	// If the hostFD can return EWOULDBLOCK when set to non-blocking, do so and
	// handle blocking behavior in the sentry.
	if i.mayBlock {
		if err := unix.SetNonblock(i.hostFD, true); err != nil {
			return nil, err
		}
		if err := fdnotifier.AddFD(int32(i.hostFD), &i.queue); err != nil {
			return nil, err
		}
	}
	return i, nil
}

// NewFDOptions contains options to NewFD.
type NewFDOptions struct {
	// If Savable is true, the host file descriptor may be saved/restored by
	// numeric value; the sandbox API requires a corresponding host FD with the
	// same numeric value to be provieded at time of restore.
	Savable bool

	// If IsTTY is true, the file descriptor is a TTY.
	IsTTY bool

	// If HaveFlags is true, use Flags for the new file description. Otherwise,
	// the new file description will inherit flags from hostFD.
	HaveFlags bool
	Flags     uint32
}

// NewFD returns a vfs.FileDescription representing the given host file
// descriptor. mnt must be Kernel.HostMount().
func NewFD(ctx context.Context, mnt *vfs.Mount, hostFD int, opts *NewFDOptions) (*vfs.FileDescription, error) {
	fs, ok := mnt.Filesystem().Impl().(*filesystem)
	if !ok {
		return nil, fmt.Errorf("can't import host FDs into filesystems of type %T", mnt.Filesystem().Impl())
	}

	// Retrieve metadata.
	var s unix.Stat_t
	if err := unix.Fstat(hostFD, &s); err != nil {
		return nil, err
	}

	flags := opts.Flags
	if !opts.HaveFlags {
		// Get flags for the imported FD.
		flagsInt, err := unix.FcntlInt(uintptr(hostFD), unix.F_GETFL, 0)
		if err != nil {
			return nil, err
		}
		flags = uint32(flagsInt)
	}

	d := &kernfs.Dentry{}
	i, err := newInode(ctx, fs, hostFD, opts.Savable, linux.FileMode(s.Mode).FileType(), opts.IsTTY)
	if err != nil {
		return nil, err
	}
	d.Init(&fs.Filesystem, i)

	// i.open will take a reference on d.
	defer d.DecRef(ctx)

	// For simplicity, fileDescription.offset is set to 0. Technically, we
	// should only set to 0 on files that are not seekable (sockets, pipes,
	// etc.), and use the offset from the host fd otherwise when importing.
	return i.open(ctx, d, mnt, flags)
}

// ImportFD sets up and returns a vfs.FileDescription from a donated fd.
func ImportFD(ctx context.Context, mnt *vfs.Mount, hostFD int, isTTY bool) (*vfs.FileDescription, error) {
	return NewFD(ctx, mnt, hostFD, &NewFDOptions{
		Savable: true,
		IsTTY:   isTTY,
	})
}

// filesystemType implements vfs.FilesystemType.
//
// +stateify savable
type filesystemType struct{}

// GetFilesystem implements vfs.FilesystemType.GetFilesystem.
func (filesystemType) GetFilesystem(context.Context, *vfs.VirtualFilesystem, *auth.Credentials, string, vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	panic("host.filesystemType.GetFilesystem should never be called")
}

// Name implements vfs.FilesystemType.Name.
func (filesystemType) Name() string {
	return "none"
}

// Release implements vfs.FilesystemType.Release.
func (filesystemType) Release(ctx context.Context) {}

// NewFilesystem sets up and returns a new hostfs filesystem.
//
// Note that there should only ever be one instance of host.filesystem,
// a global mount for host fds.
func NewFilesystem(vfsObj *vfs.VirtualFilesystem) (*vfs.Filesystem, error) {
	devMinor, err := vfsObj.GetAnonBlockDevMinor()
	if err != nil {
		return nil, err
	}
	fs := &filesystem{
		devMinor: devMinor,
	}
	fs.VFSFilesystem().Init(vfsObj, filesystemType{}, fs)
	return fs.VFSFilesystem(), nil
}

// filesystem implements vfs.FilesystemImpl.
//
// +stateify savable
type filesystem struct {
	kernfs.Filesystem

	devMinor uint32
}

func (fs *filesystem) Release(ctx context.Context) {
	fs.VFSFilesystem().VirtualFilesystem().PutAnonBlockDevMinor(fs.devMinor)
	fs.Filesystem.Release(ctx)
}

func (fs *filesystem) PrependPath(ctx context.Context, vfsroot, vd vfs.VirtualDentry, b *fspath.Builder) error {
	d := vd.Dentry().Impl().(*kernfs.Dentry)
	inode := d.Inode().(*inode)
	b.PrependComponent(fmt.Sprintf("host:[%d]", inode.ino))
	return vfs.PrependPathSyntheticError{}
}

// MountOptions implements vfs.FilesystemImpl.MountOptions.
func (fs *filesystem) MountOptions() string {
	return ""
}

// CheckPermissions implements kernfs.Inode.CheckPermissions.
func (i *inode) CheckPermissions(ctx context.Context, creds *auth.Credentials, ats vfs.AccessTypes) error {
	var s unix.Stat_t
	if err := unix.Fstat(i.hostFD, &s); err != nil {
		return err
	}
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(s.Mode), auth.KUID(s.Uid), auth.KGID(s.Gid))
}

// Mode implements kernfs.Inode.Mode.
func (i *inode) Mode() linux.FileMode {
	var s unix.Stat_t
	if err := unix.Fstat(i.hostFD, &s); err != nil {
		// Retrieving the mode from the host fd using fstat(2) should not fail.
		// If the syscall does not succeed, something is fundamentally wrong.
		panic(fmt.Sprintf("failed to retrieve mode from host fd %d: %v", i.hostFD, err))
	}
	return linux.FileMode(s.Mode)
}

// Stat implements kernfs.Inode.Stat.
func (i *inode) Stat(ctx context.Context, vfsfs *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	if opts.Mask&linux.STATX__RESERVED != 0 {
		return linux.Statx{}, syserror.EINVAL
	}
	if opts.Sync&linux.AT_STATX_SYNC_TYPE == linux.AT_STATX_SYNC_TYPE {
		return linux.Statx{}, syserror.EINVAL
	}

	fs := vfsfs.Impl().(*filesystem)

	// Limit our host call only to known flags.
	mask := opts.Mask & linux.STATX_ALL
	var s unix.Statx_t
	err := unix.Statx(i.hostFD, "", int(unix.AT_EMPTY_PATH|opts.Sync), int(mask), &s)
	if linuxerr.Equals(linuxerr.ENOSYS, err) {
		// Fallback to fstat(2), if statx(2) is not supported on the host.
		//
		// TODO(b/151263641): Remove fallback.
		return i.fstat(fs)
	}
	if err != nil {
		return linux.Statx{}, err
	}

	// Unconditionally fill blksize, attributes, and device numbers, as
	// indicated by /include/uapi/linux/stat.h. Inode number is always
	// available, since we use our own rather than the host's.
	ls := linux.Statx{
		Mask:           linux.STATX_INO,
		Blksize:        s.Blksize,
		Attributes:     s.Attributes,
		Ino:            i.ino,
		AttributesMask: s.Attributes_mask,
		DevMajor:       linux.UNNAMED_MAJOR,
		DevMinor:       fs.devMinor,
	}

	// Copy other fields that were returned by the host. RdevMajor/RdevMinor
	// are never copied (and therefore left as zero), so as not to expose host
	// device numbers.
	ls.Mask |= s.Mask & linux.STATX_ALL
	if s.Mask&linux.STATX_TYPE != 0 {
		ls.Mode |= s.Mode & linux.S_IFMT
	}
	if s.Mask&linux.STATX_MODE != 0 {
		ls.Mode |= s.Mode &^ linux.S_IFMT
	}
	if s.Mask&linux.STATX_NLINK != 0 {
		ls.Nlink = s.Nlink
	}
	if s.Mask&linux.STATX_UID != 0 {
		ls.UID = s.Uid
	}
	if s.Mask&linux.STATX_GID != 0 {
		ls.GID = s.Gid
	}
	if s.Mask&linux.STATX_ATIME != 0 {
		ls.Atime = unixToLinuxStatxTimestamp(s.Atime)
	}
	if s.Mask&linux.STATX_BTIME != 0 {
		ls.Btime = unixToLinuxStatxTimestamp(s.Btime)
	}
	if s.Mask&linux.STATX_CTIME != 0 {
		ls.Ctime = unixToLinuxStatxTimestamp(s.Ctime)
	}
	if s.Mask&linux.STATX_MTIME != 0 {
		ls.Mtime = unixToLinuxStatxTimestamp(s.Mtime)
	}
	if s.Mask&linux.STATX_SIZE != 0 {
		ls.Size = s.Size
	}
	if s.Mask&linux.STATX_BLOCKS != 0 {
		ls.Blocks = s.Blocks
	}

	return ls, nil
}

// fstat is a best-effort fallback for inode.Stat() if the host does not
// support statx(2).
//
// We ignore the mask and sync flags in opts and simply supply
// STATX_BASIC_STATS, as fstat(2) itself does not allow the specification
// of a mask or sync flags. fstat(2) does not provide any metadata
// equivalent to Statx.Attributes, Statx.AttributesMask, or Statx.Btime, so
// those fields remain empty.
func (i *inode) fstat(fs *filesystem) (linux.Statx, error) {
	var s unix.Stat_t
	if err := unix.Fstat(i.hostFD, &s); err != nil {
		return linux.Statx{}, err
	}

	// As with inode.Stat(), we always use internal device and inode numbers,
	// and never expose the host's represented device numbers.
	return linux.Statx{
		Mask:     linux.STATX_BASIC_STATS,
		Blksize:  uint32(s.Blksize),
		Nlink:    uint32(s.Nlink),
		UID:      s.Uid,
		GID:      s.Gid,
		Mode:     uint16(s.Mode),
		Ino:      i.ino,
		Size:     uint64(s.Size),
		Blocks:   uint64(s.Blocks),
		Atime:    timespecToStatxTimestamp(s.Atim),
		Ctime:    timespecToStatxTimestamp(s.Ctim),
		Mtime:    timespecToStatxTimestamp(s.Mtim),
		DevMajor: linux.UNNAMED_MAJOR,
		DevMinor: fs.devMinor,
	}, nil
}

// SetStat implements kernfs.Inode.SetStat.
func (i *inode) SetStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	s := &opts.Stat

	m := s.Mask
	if m == 0 {
		return nil
	}
	if m&^(linux.STATX_MODE|linux.STATX_SIZE|linux.STATX_ATIME|linux.STATX_MTIME) != 0 {
		return syserror.EPERM
	}
	var hostStat unix.Stat_t
	if err := unix.Fstat(i.hostFD, &hostStat); err != nil {
		return err
	}
	if err := vfs.CheckSetStat(ctx, creds, &opts, linux.FileMode(hostStat.Mode), auth.KUID(hostStat.Uid), auth.KGID(hostStat.Gid)); err != nil {
		return err
	}

	if m&linux.STATX_MODE != 0 {
		if err := unix.Fchmod(i.hostFD, uint32(s.Mode)); err != nil {
			return err
		}
	}
	if m&linux.STATX_SIZE != 0 {
		if hostStat.Mode&linux.S_IFMT != linux.S_IFREG {
			return syserror.EINVAL
		}
		if err := unix.Ftruncate(i.hostFD, int64(s.Size)); err != nil {
			return err
		}
		oldSize := uint64(hostStat.Size)
		if s.Size < oldSize {
			oldpgend, _ := hostarch.PageRoundUp(oldSize)
			newpgend, _ := hostarch.PageRoundUp(s.Size)
			if oldpgend != newpgend {
				i.CachedMappable.InvalidateRange(memmap.MappableRange{newpgend, oldpgend})
			}
		}
	}
	if m&(linux.STATX_ATIME|linux.STATX_MTIME) != 0 {
		ts := [2]unix.Timespec{
			toTimespec(s.Atime, m&linux.STATX_ATIME == 0),
			toTimespec(s.Mtime, m&linux.STATX_MTIME == 0),
		}
		if err := setTimestamps(i.hostFD, &ts); err != nil {
			return err
		}
	}
	return nil
}

// DecRef implements kernfs.Inode.DecRef.
func (i *inode) DecRef(ctx context.Context) {
	i.inodeRefs.DecRef(func() {
		if i.mayBlock {
			fdnotifier.RemoveFD(int32(i.hostFD))
		}
		if err := unix.Close(i.hostFD); err != nil {
			log.Warningf("failed to close host fd %d: %v", i.hostFD, err)
		}
		// We can't rely on fdnotifier when closing the fd, because the event may race
		// with fdnotifier.RemoveFD. Instead, notify the queue explicitly.
		i.queue.Notify(waiter.EventHUp | waiter.ReadableEvents | waiter.WritableEvents)
	})
}

// Open implements kernfs.Inode.Open.
func (i *inode) Open(ctx context.Context, rp *vfs.ResolvingPath, d *kernfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	// Once created, we cannot re-open a socket fd through /proc/[pid]/fd/.
	if i.Mode().FileType() == linux.S_IFSOCK {
		return nil, syserror.ENXIO
	}
	return i.open(ctx, d, rp.Mount(), opts.Flags)
}

func (i *inode) open(ctx context.Context, d *kernfs.Dentry, mnt *vfs.Mount, flags uint32) (*vfs.FileDescription, error) {
	var s unix.Stat_t
	if err := unix.Fstat(i.hostFD, &s); err != nil {
		return nil, err
	}
	fileType := s.Mode & linux.FileTypeMask

	// Constrain flags to a subset we can handle.
	//
	// TODO(gvisor.dev/issue/2601): Support O_NONBLOCK by adding RWF_NOWAIT to pread/pwrite calls.
	flags &= unix.O_ACCMODE | unix.O_NONBLOCK | unix.O_DSYNC | unix.O_SYNC | unix.O_APPEND

	switch fileType {
	case unix.S_IFSOCK:
		if i.isTTY {
			log.Warningf("cannot use host socket fd %d as TTY", i.hostFD)
			return nil, syserror.ENOTTY
		}

		ep, err := newEndpoint(ctx, i.hostFD, &i.queue)
		if err != nil {
			return nil, err
		}
		// Currently, we only allow Unix sockets to be imported.
		return unixsocket.NewFileDescription(ep, ep.Type(), flags, mnt, d.VFSDentry(), &i.locks)

	case unix.S_IFREG, unix.S_IFIFO, unix.S_IFCHR:
		if i.isTTY {
			fd := &TTYFileDescription{
				fileDescription: fileDescription{inode: i},
				termios:         linux.DefaultReplicaTermios,
			}
			if task := kernel.TaskFromContext(ctx); task != nil {
				fd.fgProcessGroup = task.ThreadGroup().ProcessGroup()
				fd.session = fd.fgProcessGroup.Session()
			}
			fd.LockFD.Init(&i.locks)
			vfsfd := &fd.vfsfd
			if err := vfsfd.Init(fd, flags, mnt, d.VFSDentry(), &vfs.FileDescriptionOptions{}); err != nil {
				return nil, err
			}
			return vfsfd, nil
		}

		fd := &fileDescription{inode: i}
		fd.LockFD.Init(&i.locks)
		vfsfd := &fd.vfsfd
		if err := vfsfd.Init(fd, flags, mnt, d.VFSDentry(), &vfs.FileDescriptionOptions{}); err != nil {
			return nil, err
		}
		return vfsfd, nil

	default:
		log.Warningf("cannot import host fd %d with file type %o", i.hostFD, fileType)
		return nil, syserror.EPERM
	}
}

// fileDescription is embedded by host fd implementations of FileDescriptionImpl.
//
// +stateify savable
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl
	vfs.LockFD

	// inode is vfsfd.Dentry().Impl().(*kernfs.Dentry).Inode().(*inode), but
	// cached to reduce indirections and casting. fileDescription does not hold
	// a reference on the inode through the inode field (since one is already
	// held via the Dentry).
	//
	// inode is immutable after fileDescription creation.
	inode *inode

	// offsetMu protects offset.
	offsetMu sync.Mutex `state:"nosave"`

	// offset specifies the current file offset. It is only meaningful when
	// inode.seekable is true.
	offset int64
}

// SetStat implements vfs.FileDescriptionImpl.SetStat.
func (f *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	creds := auth.CredentialsFromContext(ctx)
	return f.inode.SetStat(ctx, f.vfsfd.Mount().Filesystem(), creds, opts)
}

// Stat implements vfs.FileDescriptionImpl.Stat.
func (f *fileDescription) Stat(ctx context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	return f.inode.Stat(ctx, f.vfsfd.Mount().Filesystem(), opts)
}

// Release implements vfs.FileDescriptionImpl.Release.
func (f *fileDescription) Release(context.Context) {
	// noop
}

// Allocate implements vfs.FileDescriptionImpl.Allocate.
func (f *fileDescription) Allocate(ctx context.Context, mode, offset, length uint64) error {
	return unix.Fallocate(f.inode.hostFD, uint32(mode), int64(offset), int64(length))
}

// PRead implements vfs.FileDescriptionImpl.PRead.
func (f *fileDescription) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select preadv2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, syserror.EOPNOTSUPP
	}

	i := f.inode
	if !i.seekable {
		return 0, syserror.ESPIPE
	}

	return readFromHostFD(ctx, i.hostFD, dst, offset, opts.Flags)
}

// Read implements vfs.FileDescriptionImpl.Read.
func (f *fileDescription) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	// Check that flags are supported.
	//
	// TODO(gvisor.dev/issue/2601): Support select preadv2 flags.
	if opts.Flags&^linux.RWF_HIPRI != 0 {
		return 0, syserror.EOPNOTSUPP
	}

	i := f.inode
	if !i.seekable {
		bufN, err := i.readFromBuf(ctx, &dst)
		if err != nil {
			return bufN, err
		}
		n, err := readFromHostFD(ctx, i.hostFD, dst, -1, opts.Flags)
		total := bufN + n
		if isBlockError(err) {
			// If we got any data at all, return it as a "completed" partial read
			// rather than retrying until complete.
			if total != 0 {
				err = nil
			} else {
				err = syserror.ErrWouldBlock
			}
		}
		return total, err
	}

	f.offsetMu.Lock()
	n, err := readFromHostFD(ctx, i.hostFD, dst, f.offset, opts.Flags)
	f.offset += n
	f.offsetMu.Unlock()
	return n, err
}

func (i *inode) readFromBuf(ctx context.Context, dst *usermem.IOSequence) (int64, error) {
	if atomic.LoadUint32(&i.haveBuf) == 0 {
		return 0, nil
	}
	i.bufMu.Lock()
	defer i.bufMu.Unlock()
	if len(i.buf) == 0 {
		return 0, nil
	}
	n, err := dst.CopyOut(ctx, i.buf)
	*dst = dst.DropFirst(n)
	i.buf = i.buf[n:]
	if len(i.buf) == 0 {
		atomic.StoreUint32(&i.haveBuf, 0)
		i.buf = nil
	}
	return int64(n), err
}

func readFromHostFD(ctx context.Context, hostFD int, dst usermem.IOSequence, offset int64, flags uint32) (int64, error) {
	reader := hostfd.GetReadWriterAt(int32(hostFD), offset, flags)
	n, err := dst.CopyOutFrom(ctx, reader)
	hostfd.PutReadWriterAt(reader)
	return int64(n), err
}

// PWrite implements vfs.FileDescriptionImpl.PWrite.
func (f *fileDescription) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	if !f.inode.seekable {
		return 0, syserror.ESPIPE
	}

	return f.writeToHostFD(ctx, src, offset, opts.Flags)
}

// Write implements vfs.FileDescriptionImpl.Write.
func (f *fileDescription) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	i := f.inode
	if !i.seekable {
		n, err := f.writeToHostFD(ctx, src, -1, opts.Flags)
		if isBlockError(err) {
			err = syserror.ErrWouldBlock
		}
		return n, err
	}

	f.offsetMu.Lock()
	// NOTE(gvisor.dev/issue/2983): O_APPEND may cause memory corruption if
	// another process modifies the host file between retrieving the file size
	// and writing to the host fd. This is an unavoidable race condition because
	// we cannot enforce synchronization on the host.
	if f.vfsfd.StatusFlags()&linux.O_APPEND != 0 {
		var s unix.Stat_t
		if err := unix.Fstat(i.hostFD, &s); err != nil {
			f.offsetMu.Unlock()
			return 0, err
		}
		f.offset = s.Size
	}
	n, err := f.writeToHostFD(ctx, src, f.offset, opts.Flags)
	f.offset += n
	f.offsetMu.Unlock()
	return n, err
}

func (f *fileDescription) writeToHostFD(ctx context.Context, src usermem.IOSequence, offset int64, flags uint32) (int64, error) {
	hostFD := f.inode.hostFD
	// TODO(gvisor.dev/issue/2601): Support select pwritev2 flags.
	if flags != 0 {
		return 0, syserror.EOPNOTSUPP
	}
	writer := hostfd.GetReadWriterAt(int32(hostFD), offset, flags)
	n, err := src.CopyInTo(ctx, writer)
	hostfd.PutReadWriterAt(writer)
	// NOTE(gvisor.dev/issue/2979): We always sync everything, even for O_DSYNC.
	if n > 0 && f.vfsfd.StatusFlags()&(linux.O_DSYNC|linux.O_SYNC) != 0 {
		if syncErr := unix.Fsync(hostFD); syncErr != nil {
			return int64(n), syncErr
		}
	}
	return int64(n), err
}

// Seek implements vfs.FileDescriptionImpl.Seek.
//
// Note that we do not support seeking on directories, since we do not even
// allow directory fds to be imported at all.
func (f *fileDescription) Seek(_ context.Context, offset int64, whence int32) (int64, error) {
	i := f.inode
	if !i.seekable {
		return 0, syserror.ESPIPE
	}

	f.offsetMu.Lock()
	defer f.offsetMu.Unlock()

	switch whence {
	case linux.SEEK_SET:
		if offset < 0 {
			return f.offset, syserror.EINVAL
		}
		f.offset = offset

	case linux.SEEK_CUR:
		// Check for overflow. Note that underflow cannot occur, since f.offset >= 0.
		if offset > math.MaxInt64-f.offset {
			return f.offset, syserror.EOVERFLOW
		}
		if f.offset+offset < 0 {
			return f.offset, syserror.EINVAL
		}
		f.offset += offset

	case linux.SEEK_END:
		var s unix.Stat_t
		if err := unix.Fstat(i.hostFD, &s); err != nil {
			return f.offset, err
		}
		size := s.Size

		// Check for overflow. Note that underflow cannot occur, since size >= 0.
		if offset > math.MaxInt64-size {
			return f.offset, syserror.EOVERFLOW
		}
		if size+offset < 0 {
			return f.offset, syserror.EINVAL
		}
		f.offset = size + offset

	case linux.SEEK_DATA, linux.SEEK_HOLE:
		// Modifying the offset in the host file table should not matter, since
		// this is the only place where we use it.
		//
		// For reading and writing, we always rely on our internal offset.
		n, err := unix.Seek(i.hostFD, offset, int(whence))
		if err != nil {
			return f.offset, err
		}
		f.offset = n

	default:
		// Invalid whence.
		return f.offset, syserror.EINVAL
	}

	return f.offset, nil
}

// Sync implements vfs.FileDescriptionImpl.Sync.
func (f *fileDescription) Sync(ctx context.Context) error {
	// TODO(gvisor.dev/issue/1897): Currently, we always sync everything.
	return unix.Fsync(f.inode.hostFD)
}

// ConfigureMMap implements vfs.FileDescriptionImpl.ConfigureMMap.
func (f *fileDescription) ConfigureMMap(_ context.Context, opts *memmap.MMapOpts) error {
	// NOTE(b/38213152): Technically, some obscure char devices can be memory
	// mapped, but we only allow regular files.
	if f.inode.ftype != unix.S_IFREG {
		return syserror.ENODEV
	}
	i := f.inode
	i.CachedMappable.InitFileMapperOnce()
	return vfs.GenericConfigureMMap(&f.vfsfd, i, opts)
}

// EventRegister implements waiter.Waitable.EventRegister.
func (f *fileDescription) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	f.inode.queue.EventRegister(e, mask)
	if f.inode.mayBlock {
		fdnotifier.UpdateFD(int32(f.inode.hostFD))
	}
}

// EventUnregister implements waiter.Waitable.EventUnregister.
func (f *fileDescription) EventUnregister(e *waiter.Entry) {
	f.inode.queue.EventUnregister(e)
	if f.inode.mayBlock {
		fdnotifier.UpdateFD(int32(f.inode.hostFD))
	}
}

// Readiness uses the poll() syscall to check the status of the underlying FD.
func (f *fileDescription) Readiness(mask waiter.EventMask) waiter.EventMask {
	return fdnotifier.NonBlockingPoll(int32(f.inode.hostFD), mask)
}
