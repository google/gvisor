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
	"syscall"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
)

// filesystem implements vfs.FilesystemImpl.
type filesystem struct {
	kernfs.Filesystem
}

// NewMount returns a new disconnected mount in vfsObj that may be passed to ImportFD.
func NewMount(vfsObj *vfs.VirtualFilesystem) (*vfs.Mount, error) {
	fs := &filesystem{}
	fs.Init(vfsObj)
	vfsfs := fs.VFSFilesystem()
	// NewDisconnectedMount will take an additional reference on vfsfs.
	defer vfsfs.DecRef()
	return vfsObj.NewDisconnectedMount(vfsfs, nil, &vfs.MountOptions{})
}

// ImportFD sets up and returns a vfs.FileDescription from a donated fd.
func ImportFD(mnt *vfs.Mount, hostFD int, ownerUID auth.KUID, ownerGID auth.KGID, isTTY bool) (*vfs.FileDescription, error) {
	fs, ok := mnt.Filesystem().Impl().(*kernfs.Filesystem)
	if !ok {
		return nil, fmt.Errorf("can't import host FDs into filesystems of type %T", mnt.Filesystem().Impl())
	}

	// Retrieve metadata.
	var s syscall.Stat_t
	if err := syscall.Fstat(hostFD, &s); err != nil {
		return nil, err
	}

	fileMode := linux.FileMode(s.Mode)
	fileType := fileMode.FileType()
	// Pipes, character devices, and sockets.
	isStream := fileType == syscall.S_IFIFO || fileType == syscall.S_IFCHR || fileType == syscall.S_IFSOCK

	i := &inode{
		hostFD:   hostFD,
		isStream: isStream,
		isTTY:    isTTY,
		ino:      fs.NextIno(),
		mode:     fileMode,
		uid:      ownerUID,
		gid:      ownerGID,
	}

	d := &kernfs.Dentry{}
	d.Init(i)
	// i.open will take a reference on d.
	defer d.DecRef()

	return i.open(d.VFSDentry(), mnt)
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

	// isStream is true if the host fd points to a file representing a stream,
	// e.g. a socket or a pipe. Such files are not seekable and can return
	// EWOULDBLOCK for I/O operations.
	//
	// This field is initialized at creation time and is immutable.
	isStream bool

	// isTTY is true if this file represents a TTY.
	//
	// This field is initialized at creation time and is immutable.
	isTTY bool

	// ino is an inode number unique within this filesystem.
	ino uint64

	// mu protects the inode metadata below.
	// TODO(gvisor.dev/issue/1672): actually protect fields below.
	//mu sync.Mutex

	// mode is the file mode of this inode. Note that this value may become out
	// of date if the mode is changed on the host, e.g. with chmod.
	mode linux.FileMode

	// uid and gid of the file owner. Note that these refer to the owner of the
	// file created on import, not the fd on the host.
	uid auth.KUID
	gid auth.KGID
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
func (i *inode) CheckPermissions(ctx context.Context, creds *auth.Credentials, atx vfs.AccessTypes) error {
	return vfs.GenericCheckPermissions(creds, atx, false /* isDir */, uint16(i.mode), i.uid, i.gid)
}

// Mode implements kernfs.Inode.
func (i *inode) Mode() linux.FileMode {
	return i.mode
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

	if mask|linux.STATX_TYPE != 0 {
		ls.Mode |= s.Mode & linux.S_IFMT
	}
	if mask|linux.STATX_MODE != 0 {
		ls.Mode |= s.Mode &^ linux.S_IFMT
	}
	if mask|linux.STATX_NLINK != 0 {
		ls.Nlink = s.Nlink
	}
	if mask|linux.STATX_ATIME != 0 {
		ls.Atime = unixToLinuxStatxTimestamp(s.Atime)
	}
	if mask|linux.STATX_BTIME != 0 {
		ls.Btime = unixToLinuxStatxTimestamp(s.Btime)
	}
	if mask|linux.STATX_CTIME != 0 {
		ls.Ctime = unixToLinuxStatxTimestamp(s.Ctime)
	}
	if mask|linux.STATX_MTIME != 0 {
		ls.Mtime = unixToLinuxStatxTimestamp(s.Mtime)
	}
	if mask|linux.STATX_SIZE != 0 {
		ls.Size = s.Size
	}
	if mask|linux.STATX_BLOCKS != 0 {
		ls.Blocks = s.Blocks
	}

	// Use our own internal inode number and file owner.
	if mask|linux.STATX_INO != 0 {
		ls.Ino = i.ino
	}
	if mask|linux.STATX_UID != 0 {
		ls.UID = uint32(i.uid)
	}
	if mask|linux.STATX_GID != 0 {
		ls.GID = uint32(i.gid)
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
		Mode:    uint16(s.Mode),
		Size:    uint64(s.Size),
		Blocks:  uint64(s.Blocks),
		Atime:   timespecToStatxTimestamp(s.Atim),
		Ctime:   timespecToStatxTimestamp(s.Ctim),
		Mtime:   timespecToStatxTimestamp(s.Mtim),
	}

	// Use our own internal inode number and file owner.
	//
	// TODO(gvisor.dev/issue/1672): Use a kernfs-specific device number as well.
	// If we use the device number from the host, it may collide with another
	// sentry-internal device number. We handle device/inode numbers without
	// relying on the host to prevent collisions.
	ls.Ino = i.ino
	ls.UID = uint32(i.uid)
	ls.GID = uint32(i.gid)

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
	if err := vfs.CheckSetStat(ctx, creds, &s, uint16(i.Mode().Permissions()), i.uid, i.gid); err != nil {
		return err
	}

	if m&linux.STATX_MODE != 0 {
		if err := syscall.Fchmod(i.hostFD, uint32(s.Mode)); err != nil {
			return err
		}
		i.mode = linux.FileMode(s.Mode)
	}
	if m&linux.STATX_SIZE != 0 {
		if err := syscall.Ftruncate(i.hostFD, int64(s.Size)); err != nil {
			return err
		}
	}
	if m&(linux.STATX_ATIME|linux.STATX_MTIME) != 0 {
		timestamps := []unix.Timespec{
			toTimespec(s.Atime, m&linux.STATX_ATIME == 0),
			toTimespec(s.Mtime, m&linux.STATX_MTIME == 0),
		}
		if err := unix.UtimesNanoAt(i.hostFD, "", timestamps, unix.AT_EMPTY_PATH); err != nil {
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
func (i *inode) Open(rp *vfs.ResolvingPath, vfsd *vfs.Dentry, opts vfs.OpenOptions) (*vfs.FileDescription, error) {
	return i.open(vfsd, rp.Mount())
}

func (i *inode) open(d *vfs.Dentry, mnt *vfs.Mount) (*vfs.FileDescription, error) {
	fileType := i.mode.FileType()
	if fileType == syscall.S_IFSOCK {
		if i.isTTY {
			return nil, errors.New("cannot use host socket as TTY")
		}
		// TODO(gvisor.dev/issue/1672): support importing sockets.
		return nil, errors.New("importing host sockets not supported")
	}

	// TODO(gvisor.dev/issue/1672): Whitelist specific file types here, so that
	// we don't allow importing arbitrary file types without proper support.
	if i.isTTY {
		// TODO(gvisor.dev/issue/1672): support importing host fd as TTY.
		return nil, errors.New("importing host fd as TTY not supported")
	}

	// For simplicity, set offset to 0. Technically, we should
	// only set to 0 on files that are not seekable (sockets, pipes, etc.),
	// and use the offset from the host fd otherwise.
	fd := &defaultFileFD{
		fileDescription: fileDescription{
			inode: i,
		},
		canMap: canMap(uint32(fileType)),
		mu:     sync.Mutex{},
		offset: 0,
	}

	vfsfd := &fd.vfsfd
	flags, err := fileFlagsFromHostFD(i.hostFD)
	if err != nil {
		return nil, err
	}

	if err := vfsfd.Init(fd, uint32(flags), mnt, d, &vfs.FileDescriptionOptions{}); err != nil {
		return nil, err
	}
	return vfsfd, nil
}

// fileDescription is embedded by host fd implementations of FileDescriptionImpl.
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
