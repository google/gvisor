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
	"errors"
	"fmt"
	"math"
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// filesystemType implements vfs.FilesystemType.
type filesystemType struct{}

// GetFilesystem implements FilesystemType.GetFilesystem.
func (filesystemType) GetFilesystem(context.Context, *vfs.VirtualFilesystem, *auth.Credentials, string, vfs.GetFilesystemOptions) (*vfs.Filesystem, *vfs.Dentry, error) {
	panic("host.filesystemType.GetFilesystem should never be called")
}

// Name implements FilesystemType.Name.
func (filesystemType) Name() string {
	return "none"
}

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	kernfs.Filesystem
}

// NewFilesystem sets up and returns a new hostfs filesystem.
//
// Note that there should only ever be one instance of host.filesystem,
// a global mount for host fds.
func NewFilesystem(vfsObj *vfs.VirtualFilesystem) *vfs.Filesystem {
	fs := &filesystem{}
	fs.Init(vfsObj, filesystemType{})
	return fs.VFSFilesystem()
}

// ImportFD sets up and returns a vfs.FileDescription from a donated fd.
func ImportFD(ctx context.Context, mnt *vfs.Mount, hostFD int, isTTY bool) (*vfs.FileDescription, error) {
	fs, ok := mnt.Filesystem().Impl().(*kernfs.Filesystem)
	if !ok {
		return nil, fmt.Errorf("can't import host FDs into filesystems of type %T", mnt.Filesystem().Impl())
	}

	// Retrieve metadata.
	var s unix.Stat_t
	if err := unix.Fstat(hostFD, &s); err != nil {
		return nil, err
	}

	fileMode := linux.FileMode(s.Mode)
	fileType := fileMode.FileType()

	// Determine if hostFD is seekable. If not, this syscall will return ESPIPE
	// (see fs/read_write.c:llseek), e.g. for pipes, sockets, and some character
	// devices.
	_, err := unix.Seek(hostFD, 0, linux.SEEK_CUR)
	seekable := err != syserror.ESPIPE

	i := &inode{
		hostFD:   hostFD,
		seekable: seekable,
		isTTY:    isTTY,
		canMap:   canMap(uint32(fileType)),
		ino:      fs.NextIno(),
		// For simplicity, set offset to 0. Technically, we should use the existing
		// offset on the host if the file is seekable.
		offset: 0,
	}

	// Non-seekable files can't be memory mapped, assert this.
	if !i.seekable && i.canMap {
		panic("files that can return EWOULDBLOCK (sockets, pipes, etc.) cannot be memory mapped")
	}

	d := &kernfs.Dentry{}
	d.Init(i)
	// i.open will take a reference on d.
	defer d.DecRef()

	return i.open(ctx, d.VFSDentry(), mnt)
}

// inode implements kernfs.Inode.
type inode struct {
	kernfs.InodeNotDirectory
	kernfs.InodeNotSymlink

	// When the reference count reaches zero, the host fd is closed.
	refs.AtomicRefCount

	// hostFD contains the host fd that this file was originally created from,
	// which must be available at time of restore.
	//
	// This field is initialized at creation time and is immutable.
	hostFD int

	// seekable is false if the host fd points to a file representing a stream,
	// e.g. a socket or a pipe. Such files are not seekable and can return
	// EWOULDBLOCK for I/O operations.
	//
	// This field is initialized at creation time and is immutable.
	seekable bool

	// isTTY is true if this file represents a TTY.
	//
	// This field is initialized at creation time and is immutable.
	isTTY bool

	// canMap specifies whether we allow the file to be memory mapped.
	//
	// This field is initialized at creation time and is immutable.
	canMap bool

	// ino is an inode number unique within this filesystem.
	//
	// This field is initialized at creation time and is immutable.
	ino uint64

	// offsetMu protects offset.
	offsetMu sync.Mutex

	// offset specifies the current file offset.
	offset int64
}

// Note that these flags may become out of date, since they can be modified
// on the host, e.g. with fcntl.
func fileFlagsFromHostFD(fd int) (int, error) {
	flags, err := unix.FcntlInt(uintptr(fd), syscall.F_GETFL, 0)
	if err != nil {
		log.Warningf("Failed to get file flags for donated FD %d: %v", fd, err)
		return 0, err
	}
	// TODO(gvisor.dev/issue/1672): implement behavior corresponding to these allowed flags.
	flags &= syscall.O_ACCMODE | syscall.O_DIRECT | syscall.O_NONBLOCK | syscall.O_DSYNC | syscall.O_SYNC | syscall.O_APPEND
	return flags, nil
}

// CheckPermissions implements kernfs.Inode.
func (i *inode) CheckPermissions(ctx context.Context, creds *auth.Credentials, ats vfs.AccessTypes) error {
	var s syscall.Stat_t
	if err := syscall.Fstat(i.hostFD, &s); err != nil {
		return err
	}
	return vfs.GenericCheckPermissions(creds, ats, linux.FileMode(s.Mode), auth.KUID(s.Uid), auth.KGID(s.Gid))
}

// Mode implements kernfs.Inode.
func (i *inode) Mode() linux.FileMode {
	var s syscall.Stat_t
	if err := syscall.Fstat(i.hostFD, &s); err != nil {
		// Retrieving the mode from the host fd using fstat(2) should not fail.
		// If the syscall does not succeed, something is fundamentally wrong.
		panic(fmt.Sprintf("failed to retrieve mode from host fd %d: %v", i.hostFD, err))
	}
	return linux.FileMode(s.Mode)
}

// Stat implements kernfs.Inode.
func (i *inode) Stat(_ *vfs.Filesystem, opts vfs.StatOptions) (linux.Statx, error) {
	if opts.Mask&linux.STATX__RESERVED != 0 {
		return linux.Statx{}, syserror.EINVAL
	}
	if opts.Sync&linux.AT_STATX_SYNC_TYPE == linux.AT_STATX_SYNC_TYPE {
		return linux.Statx{}, syserror.EINVAL
	}

	// Limit our host call only to known flags.
	mask := opts.Mask & linux.STATX_ALL
	var s unix.Statx_t
	err := unix.Statx(i.hostFD, "", int(unix.AT_EMPTY_PATH|opts.Sync), int(mask), &s)
	// Fallback to fstat(2), if statx(2) is not supported on the host.
	//
	// TODO(b/151263641): Remove fallback.
	if err == syserror.ENOSYS {
		return i.fstat(opts)
	} else if err != nil {
		return linux.Statx{}, err
	}

	ls := linux.Statx{Mask: mask}
	// Unconditionally fill blksize, attributes, and device numbers, as indicated
	// by /include/uapi/linux/stat.h.
	//
	// RdevMajor/RdevMinor are left as zero, so as not to expose host device
	// numbers.
	//
	// TODO(gvisor.dev/issue/1672): Use kernfs-specific, internally defined
	// device numbers. If we use the device number from the host, it may collide
	// with another sentry-internal device number. We handle device/inode
	// numbers without relying on the host to prevent collisions.
	ls.Blksize = s.Blksize
	ls.Attributes = s.Attributes
	ls.AttributesMask = s.Attributes_mask

	if mask&linux.STATX_TYPE != 0 {
		ls.Mode |= s.Mode & linux.S_IFMT
	}
	if mask&linux.STATX_MODE != 0 {
		ls.Mode |= s.Mode &^ linux.S_IFMT
	}
	if mask&linux.STATX_NLINK != 0 {
		ls.Nlink = s.Nlink
	}
	if mask&linux.STATX_UID != 0 {
		ls.UID = s.Uid
	}
	if mask&linux.STATX_GID != 0 {
		ls.GID = s.Gid
	}
	if mask&linux.STATX_ATIME != 0 {
		ls.Atime = unixToLinuxStatxTimestamp(s.Atime)
	}
	if mask&linux.STATX_BTIME != 0 {
		ls.Btime = unixToLinuxStatxTimestamp(s.Btime)
	}
	if mask&linux.STATX_CTIME != 0 {
		ls.Ctime = unixToLinuxStatxTimestamp(s.Ctime)
	}
	if mask&linux.STATX_MTIME != 0 {
		ls.Mtime = unixToLinuxStatxTimestamp(s.Mtime)
	}
	if mask&linux.STATX_SIZE != 0 {
		ls.Size = s.Size
	}
	if mask&linux.STATX_BLOCKS != 0 {
		ls.Blocks = s.Blocks
	}

	// Use our own internal inode number.
	if mask&linux.STATX_INO != 0 {
		ls.Ino = i.ino
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
func (i *inode) fstat(opts vfs.StatOptions) (linux.Statx, error) {
	var s unix.Stat_t
	if err := unix.Fstat(i.hostFD, &s); err != nil {
		return linux.Statx{}, err
	}

	// Note that rdev numbers are left as 0; do not expose host device numbers.
	ls := linux.Statx{
		Mask:    linux.STATX_BASIC_STATS,
		Blksize: uint32(s.Blksize),
		Nlink:   uint32(s.Nlink),
		UID:     s.Uid,
		GID:     s.Gid,
		Mode:    uint16(s.Mode),
		Size:    uint64(s.Size),
		Blocks:  uint64(s.Blocks),
		Atime:   timespecToStatxTimestamp(s.Atim),
		Ctime:   timespecToStatxTimestamp(s.Ctim),
		Mtime:   timespecToStatxTimestamp(s.Mtim),
	}

	// Use our own internal inode number.
	//
	// TODO(gvisor.dev/issue/1672): Use a kernfs-specific device number as well.
	// If we use the device number from the host, it may collide with another
	// sentry-internal device number. We handle device/inode numbers without
	// relying on the host to prevent collisions.
	ls.Ino = i.ino

	return ls, nil
}

// SetStat implements kernfs.Inode.
func (i *inode) SetStat(ctx context.Context, fs *vfs.Filesystem, creds *auth.Credentials, opts vfs.SetStatOptions) error {
	s := opts.Stat

	m := s.Mask
	if m == 0 {
		return nil
	}
	if m&^(linux.STATX_MODE|linux.STATX_SIZE|linux.STATX_ATIME|linux.STATX_MTIME) != 0 {
		return syserror.EPERM
	}
	var hostStat syscall.Stat_t
	if err := syscall.Fstat(i.hostFD, &hostStat); err != nil {
		return err
	}
	if err := vfs.CheckSetStat(ctx, creds, &s, linux.FileMode(hostStat.Mode&linux.PermissionsMask), auth.KUID(hostStat.Uid), auth.KGID(hostStat.Gid)); err != nil {
		return err
	}

	if m&linux.STATX_MODE != 0 {
		if err := syscall.Fchmod(i.hostFD, uint32(s.Mode)); err != nil {
			return err
		}
	}
	if m&linux.STATX_SIZE != 0 {
		if err := syscall.Ftruncate(i.hostFD, int64(s.Size)); err != nil {
			return err
		}
	}
	if m&(linux.STATX_ATIME|linux.STATX_MTIME) != 0 {
		ts := [2]syscall.Timespec{
			toTimespec(s.Atime, m&linux.STATX_ATIME == 0),
			toTimespec(s.Mtime, m&linux.STATX_MTIME == 0),
		}
		if err := setTimestamps(i.hostFD, &ts); err != nil {
			return err
		}
	}
	return nil
}

// DecRef implements kernfs.Inode.
func (i *inode) DecRef() {
	i.AtomicRefCount.DecRefWithDestructor(i.Destroy)
}

// Destroy implements kernfs.Inode.
func (i *inode) Destroy() {
	if err := unix.Close(i.hostFD); err != nil {
		log.Warningf("failed to close host fd %d: %v", i.hostFD, err)
	}
}

// Open implements kernfs.Inode.
func (i *inode) Open(ctx context.Context, rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	return i.open(ctx, vfsd, rp.Mount())
}

func (i *inode) open(ctx context.Context, d *vfs.Dentry, mnt *vfs.Mount) (*vfs.FileDescription, error) {
	var s syscall.Stat_t
	if err := syscall.Fstat(i.hostFD, &s); err != nil {
		return nil, err
	}
	fileType := s.Mode & linux.FileTypeMask
	if fileType == syscall.S_IFSOCK {
		if i.isTTY {
			return nil, errors.New("cannot use host socket as TTY")
		}
		// TODO(gvisor.dev/issue/1672): support importing sockets.
		return nil, errors.New("importing host sockets not supported")
	}

	// TODO(gvisor.dev/issue/1672): Whitelist specific file types here, so that
	// we don't allow importing arbitrary file types without proper support.
	var (
		vfsfd  *vfs.FileDescription
		fdImpl vfs.FileDescriptionImpl
	)
	if i.isTTY {
		fd := &ttyFD{
			fileDescription: fileDescription{inode: i},
			termios:         linux.DefaultSlaveTermios,
		}
		vfsfd = &fd.vfsfd
		fdImpl = fd
	} else {
		// For simplicity, set offset to 0. Technically, we should
		// only set to 0 on files that are not seekable (sockets, pipes, etc.),
		// and use the offset from the host fd otherwise.
		fd := &fileDescription{inode: i}
		vfsfd = &fd.vfsfd
		fdImpl = fd
	}

	flags, err := fileFlagsFromHostFD(i.hostFD)
	if err != nil {
		return nil, err
	}

	if err := vfsfd.Init(fdImpl, uint32(flags), mnt, d, &vfs.FileDescriptionOptions{}); err != nil {
		return nil, err
	}
	return vfsfd, nil
}

// fileDescription is embedded by host fd implementations of FileDescriptionImpl.
//
// TODO(gvisor.dev/issue/1672): Implement Waitable interface.
type fileDescription struct {
	vfsfd vfs.FileDescription
	vfs.FileDescriptionDefaultImpl

	// inode is vfsfd.Dentry().Impl().(*kernfs.Dentry).Inode().(*inode), but
	// cached to reduce indirections and casting. fileDescription does not hold
	// a reference on the inode through the inode field (since one is already
	// held via the Dentry).
	//
	// inode is immutable after fileDescription creation.
	inode *inode
}

// SetStat implements vfs.FileDescriptionImpl.
func (f *fileDescription) SetStat(ctx context.Context, opts vfs.SetStatOptions) error {
	creds := auth.CredentialsFromContext(ctx)
	return f.inode.SetStat(ctx, nil, creds, opts)
}

// Stat implements vfs.FileDescriptionImpl.
func (f *fileDescription) Stat(_ context.Context, opts vfs.StatOptions) (linux.Statx, error) {
	return f.inode.Stat(nil, opts)
}

// Release implements vfs.FileDescriptionImpl.
func (f *fileDescription) Release() {
	// noop
}

// PRead implements FileDescriptionImpl.
func (f *fileDescription) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts vfs.ReadOptions) (int64, error) {
	i := f.inode
	if !i.seekable {
		return 0, syserror.ESPIPE
	}

	return readFromHostFD(ctx, i.hostFD, dst, offset, opts.Flags)
}

// Read implements FileDescriptionImpl.
func (f *fileDescription) Read(ctx context.Context, dst usermem.IOSequence, opts vfs.ReadOptions) (int64, error) {
	i := f.inode
	if !i.seekable {
		n, err := readFromHostFD(ctx, i.hostFD, dst, -1, opts.Flags)
		if isBlockError(err) {
			// If we got any data at all, return it as a "completed" partial read
			// rather than retrying until complete.
			if n != 0 {
				err = nil
			} else {
				err = syserror.ErrWouldBlock
			}
		}
		return n, err
	}
	// TODO(gvisor.dev/issue/1672): Cache pages, when forced to do so.
	i.offsetMu.Lock()
	n, err := readFromHostFD(ctx, i.hostFD, dst, i.offset, opts.Flags)
	i.offset += n
	i.offsetMu.Unlock()
	return n, err
}

func readFromHostFD(ctx context.Context, hostFD int, dst usermem.IOSequence, offset int64, flags uint32) (int64, error) {
	// TODO(gvisor.dev/issue/1672): Support select preadv2 flags.
	if flags != 0 {
		return 0, syserror.EOPNOTSUPP
	}
	reader := hostfd.GetReadWriterAt(int32(hostFD), offset, flags)
	n, err := dst.CopyOutFrom(ctx, reader)
	hostfd.PutReadWriterAt(reader)
	return int64(n), err
}

// PWrite implements FileDescriptionImpl.
func (f *fileDescription) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts vfs.WriteOptions) (int64, error) {
	i := f.inode
	if !i.seekable {
		return 0, syserror.ESPIPE
	}

	return writeToHostFD(ctx, i.hostFD, src, offset, opts.Flags)
}

// Write implements FileDescriptionImpl.
func (f *fileDescription) Write(ctx context.Context, src usermem.IOSequence, opts vfs.WriteOptions) (int64, error) {
	i := f.inode
	if !i.seekable {
		n, err := writeToHostFD(ctx, i.hostFD, src, -1, opts.Flags)
		if isBlockError(err) {
			err = syserror.ErrWouldBlock
		}
		return n, err
	}
	// TODO(gvisor.dev/issue/1672): Cache pages, when forced to do so.
	// TODO(gvisor.dev/issue/1672): Write to end of file and update offset if O_APPEND is set on this file.
	i.offsetMu.Lock()
	n, err := writeToHostFD(ctx, i.hostFD, src, i.offset, opts.Flags)
	i.offset += n
	i.offsetMu.Unlock()
	return n, err
}

func writeToHostFD(ctx context.Context, hostFD int, src usermem.IOSequence, offset int64, flags uint32) (int64, error) {
	// TODO(gvisor.dev/issue/1672): Support select pwritev2 flags.
	if flags != 0 {
		return 0, syserror.EOPNOTSUPP
	}
	writer := hostfd.GetReadWriterAt(int32(hostFD), offset, flags)
	n, err := src.CopyInTo(ctx, writer)
	hostfd.PutReadWriterAt(writer)
	return int64(n), err
}

// Seek implements FileDescriptionImpl.
//
// Note that we do not support seeking on directories, since we do not even
// allow directory fds to be imported at all.
func (f *fileDescription) Seek(_ context.Context, offset int64, whence int32) (int64, error) {
	i := f.inode
	if !i.seekable {
		return 0, syserror.ESPIPE
	}

	i.offsetMu.Lock()
	defer i.offsetMu.Unlock()

	switch whence {
	case linux.SEEK_SET:
		if offset < 0 {
			return i.offset, syserror.EINVAL
		}
		i.offset = offset

	case linux.SEEK_CUR:
		// Check for overflow. Note that underflow cannot occur, since i.offset >= 0.
		if offset > math.MaxInt64-i.offset {
			return i.offset, syserror.EOVERFLOW
		}
		if i.offset+offset < 0 {
			return i.offset, syserror.EINVAL
		}
		i.offset += offset

	case linux.SEEK_END:
		var s syscall.Stat_t
		if err := syscall.Fstat(i.hostFD, &s); err != nil {
			return i.offset, err
		}
		size := s.Size

		// Check for overflow. Note that underflow cannot occur, since size >= 0.
		if offset > math.MaxInt64-size {
			return i.offset, syserror.EOVERFLOW
		}
		if size+offset < 0 {
			return i.offset, syserror.EINVAL
		}
		i.offset = size + offset

	case linux.SEEK_DATA, linux.SEEK_HOLE:
		// Modifying the offset in the host file table should not matter, since
		// this is the only place where we use it.
		//
		// For reading and writing, we always rely on our internal offset.
		n, err := unix.Seek(i.hostFD, offset, int(whence))
		if err != nil {
			return i.offset, err
		}
		i.offset = n

	default:
		// Invalid whence.
		return i.offset, syserror.EINVAL
	}

	return i.offset, nil
}

// Sync implements FileDescriptionImpl.
func (f *fileDescription) Sync(context.Context) error {
	// TODO(gvisor.dev/issue/1672): Currently we do not support the SyncData optimization, so we always sync everything.
	return unix.Fsync(f.inode.hostFD)
}

// ConfigureMMap implements FileDescriptionImpl.
func (f *fileDescription) ConfigureMMap(_ context.Context, opts *memmap.MMapOpts) error {
	if !f.inode.canMap {
		return syserror.ENODEV
	}
	// TODO(gvisor.dev/issue/1672): Implement ConfigureMMap and Mappable interface.
	return syserror.ENODEV
}
