// Copyright 2021 The gVisor Authors.
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

package fsgofer

import (
	"io"
	"math"
	"path"
	"strconv"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cleanup"
	rwfd "gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
	"gvisor.dev/gvisor/pkg/p9"
)

// LisafsServer implements lisafs.ServerImpl for fsgofer.
type LisafsServer struct {
	lisafs.Server
	config Config
}

var _ lisafs.ServerImpl = (*LisafsServer)(nil)

// NewLisafsServer initializes a new lisafs server for fsgofer.
func NewLisafsServer(config Config) *LisafsServer {
	s := &LisafsServer{config: config}
	s.Server.Init(s)
	return s
}

// Mount implements lisafs.ServerImpl.Mount.
func (s *LisafsServer) Mount(c *lisafs.Connection, mountPath string) (lisafs.ControlFDImpl, lisafs.Inode, error) {
	s.RenameMu.RLock()
	defer s.RenameMu.RUnlock()

	rootFD, rootStat, err := tryStepLocked(c, mountPath, nil, func(flags int) (int, error) {
		return unix.Open(mountPath, flags, 0)
	})
	if err != nil {
		return nil, lisafs.Inode{}, err
	}

	var rootIno lisafs.Inode
	rootFD.initInodeWithStat(&rootIno, &rootStat)
	return rootFD, rootIno, nil
}

// MaxMessageSize implements lisafs.ServerImpl.MaxMessageSize.
func (s *LisafsServer) MaxMessageSize() uint32 {
	return lisafs.MaxMessageSize()
}

// SupportedMessages implements lisafs.ServerImpl.SupportedMessages.
func (s *LisafsServer) SupportedMessages() []lisafs.MID {
	// Note that Flush, FListXattr and FRemoveXattr are not supported.
	return []lisafs.MID{
		lisafs.Mount,
		lisafs.Channel,
		lisafs.FStat,
		lisafs.SetStat,
		lisafs.Walk,
		lisafs.WalkStat,
		lisafs.OpenAt,
		lisafs.OpenCreateAt,
		lisafs.Close,
		lisafs.FSync,
		lisafs.PWrite,
		lisafs.PRead,
		lisafs.MkdirAt,
		lisafs.MknodAt,
		lisafs.SymlinkAt,
		lisafs.LinkAt,
		lisafs.FStatFS,
		lisafs.FAllocate,
		lisafs.ReadLinkAt,
		lisafs.Connect,
		lisafs.UnlinkAt,
		lisafs.RenameAt,
		lisafs.Getdents64,
		lisafs.FGetXattr,
		lisafs.FSetXattr,
	}
}

// controlFDLisa implements lisafs.ControlFDImpl.
type controlFDLisa struct {
	lisafs.ControlFD

	// hostFD is the file descriptor which can be used to make host syscalls.
	hostFD int

	// writableHostFD is the file descriptor number for a writable FD opened on the
	// same FD as `hostFD`. writableHostFD must only be accessed using atomic
	// operations. It is initialized to -1, and can change in value exactly once.
	writableHostFD int32
}

var _ lisafs.ControlFDImpl = (*controlFDLisa)(nil)

// Precondition: server's rename mutex must be at least read locked.
func newControlFDLisaLocked(c *lisafs.Connection, hostFD int, parent *controlFDLisa, name string, mode linux.FileMode) *controlFDLisa {
	fd := &controlFDLisa{
		hostFD:         hostFD,
		writableHostFD: -1,
	}
	fd.ControlFD.Init(c, parent.FD(), name, mode, fd)
	return fd
}

func (fd *controlFDLisa) initInode(inode *lisafs.Inode) error {
	inode.ControlFD = fd.ID()
	return fstatTo(fd.hostFD, &inode.Stat)
}

func (fd *controlFDLisa) initInodeWithStat(inode *lisafs.Inode, unixStat *unix.Stat_t) {
	inode.ControlFD = fd.ID()
	unixToLinuxStat(unixStat, &inode.Stat)
}

func (fd *controlFDLisa) getWritableFD() (int, error) {
	if writableFD := atomic.LoadInt32(&fd.writableHostFD); writableFD != -1 {
		return int(writableFD), nil
	}

	writableFD, err := unix.Openat(int(procSelfFD.FD()), strconv.Itoa(fd.hostFD), (unix.O_WRONLY|openFlags)&^unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	if !atomic.CompareAndSwapInt32(&fd.writableHostFD, -1, int32(writableFD)) {
		// Race detected, use the new value and clean this up.
		unix.Close(writableFD)
		return int(atomic.LoadInt32(&fd.writableHostFD)), nil
	}
	return writableFD, nil
}

// FD implements lisafs.ControlFDImpl.FD.
func (fd *controlFDLisa) FD() *lisafs.ControlFD {
	if fd == nil {
		return nil
	}
	return &fd.ControlFD
}

// Close implements lisafs.ControlFDImpl.Close.
func (fd *controlFDLisa) Close(c *lisafs.Connection) {
	if fd.hostFD >= 0 {
		_ = unix.Close(fd.hostFD)
		fd.hostFD = -1
	}
	// No concurrent access is possible so no need to use atomics.
	if fd.writableHostFD >= 0 {
		_ = unix.Close(int(fd.writableHostFD))
		fd.writableHostFD = -1
	}
}

// Stat implements lisafs.ControlFDImpl.Stat.
func (fd *controlFDLisa) Stat(c *lisafs.Connection, comm lisafs.Communicator) (uint32, error) {
	var resp linux.Statx
	if err := fstatTo(fd.hostFD, &resp); err != nil {
		return 0, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// SetStat implements lisafs.ControlFDImpl.SetStat.
func (fd *controlFDLisa) SetStat(c *lisafs.Connection, comm lisafs.Communicator, stat lisafs.SetStatReq) (uint32, error) {
	var resp lisafs.SetStatResp
	if stat.Mask&unix.STATX_MODE != 0 {
		if err := unix.Fchmod(fd.hostFD, stat.Mode&^unix.S_IFMT); err != nil {
			log.Debugf("SetStat fchmod failed %q, err: %v", fd.FilePath(), err)
			resp.FailureMask |= unix.STATX_MODE
			resp.FailureErrNo = uint32(p9.ExtractErrno(err))
		}
	}

	if stat.Mask&unix.STATX_SIZE != 0 {
		// ftruncate(2) requires the FD to be open for writing.
		writableFD, err := fd.getWritableFD()
		if err == nil {
			err = unix.Ftruncate(writableFD, int64(stat.Size))
		}
		if err != nil {
			log.Debugf("SetStat ftruncate failed %q, err: %v", fd.FilePath(), err)
			resp.FailureMask |= unix.STATX_SIZE
			resp.FailureErrNo = uint32(p9.ExtractErrno(err))
		}
	}

	if stat.Mask&(unix.STATX_ATIME|unix.STATX_MTIME) != 0 {
		utimes := [2]unix.Timespec{
			{Sec: 0, Nsec: unix.UTIME_OMIT},
			{Sec: 0, Nsec: unix.UTIME_OMIT},
		}
		if stat.Mask&unix.STATX_ATIME != 0 {
			utimes[0].Sec = stat.Atime.Sec
			utimes[0].Nsec = stat.Atime.Nsec
		}
		if stat.Mask&unix.STATX_MTIME != 0 {
			utimes[1].Sec = stat.Mtime.Sec
			utimes[1].Nsec = stat.Mtime.Nsec
		}

		if fd.IsSymlink() {
			// utimensat operates different that other syscalls. To operate on a
			// symlink it *requires* AT_SYMLINK_NOFOLLOW with dirFD and a non-empty
			// name.
			c.Server().WithRenameReadLock(func() error {
				if err := utimensat(fd.ParentLocked().(*controlFDLisa).hostFD, fd.NameLocked(), utimes, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					log.Debugf("SetStat utimens failed %q, err: %v", fd.FilePathLocked(), err)
					resp.FailureMask |= (stat.Mask & (unix.STATX_ATIME | unix.STATX_MTIME))
					resp.FailureErrNo = uint32(p9.ExtractErrno(err))
				}
				return nil
			})
		} else {
			hostFD := fd.hostFD
			if fd.IsRegular() {
				// For regular files, utimensat(2) requires the FD to be open for
				// writing, see BUGS section.
				writableFD, err := fd.getWritableFD()
				if err != nil {
					return 0, err
				}
				hostFD = writableFD
			}
			// Directories and regular files can operate directly on the fd
			// using empty name.
			err := utimensat(hostFD, "", utimes, 0)
			if err != nil {
				log.Debugf("SetStat utimens failed %q, err: %v", fd.FilePath(), err)
				resp.FailureMask |= (stat.Mask & (unix.STATX_ATIME | unix.STATX_MTIME))
				resp.FailureErrNo = uint32(p9.ExtractErrno(err))
			}
		}
	}

	if stat.Mask&(unix.STATX_UID|unix.STATX_GID) != 0 {
		// "If the owner or group is specified as -1, then that ID is not changed"
		// - chown(2)
		uid := -1
		if stat.Mask&unix.STATX_UID != 0 {
			uid = int(stat.UID)
		}
		gid := -1
		if stat.Mask&unix.STATX_GID != 0 {
			gid = int(stat.GID)
		}
		if err := unix.Fchownat(fd.hostFD, "", uid, gid, unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			log.Debugf("SetStat fchown failed %q, err: %v", fd.FilePath(), err)
			resp.FailureMask |= stat.Mask & (unix.STATX_UID | unix.STATX_GID)
			resp.FailureErrNo = uint32(p9.ExtractErrno(err))
		}
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// Walk implements lisafs.ControlFDImpl.Walk.
func (fd *controlFDLisa) Walk(c *lisafs.Connection, comm lisafs.Communicator, path lisafs.StringArray) (uint32, error) {
	// We need to generate inodes for each component walked. We will manually
	// marshal the inodes into the payload buffer as they are generated to avoid
	// the slice allocation. The memory format should be lisafs.WalkResp's.
	var numInodes primitive.Uint32
	var status lisafs.WalkStatus
	maxPayloadSize := status.SizeBytes() + numInodes.SizeBytes() + (len(path) * (*lisafs.Inode)(nil).SizeBytes())
	if maxPayloadSize > math.MaxUint32 {
		// Too much to walk, can't do.
		return 0, unix.EIO
	}
	payloadBuf := comm.PayloadBuf(uint32(maxPayloadSize))
	payloadPos := status.SizeBytes() + numInodes.SizeBytes()

	s := c.Server()
	s.RenameMu.RLock()
	defer s.RenameMu.RUnlock()

	curDirFD := fd
	cu := cleanup.Make(func() {
		// Destroy all newly created FDs until now. Walk upward from curDirFD to
		// fd. Do not destroy fd as the client still owns that.
		for curDirFD != fd {
			c.RemoveControlFDLocked(curDirFD.ID())
			curDirFD = curDirFD.ParentLocked().(*controlFDLisa)
		}
	})
	defer cu.Clean()

	for _, name := range path {
		// Symlinks terminate walk. This client gets the symlink inode, but will
		// have to invoke Walk again with the resolved path.
		if curDirFD.IsSymlink() {
			status = lisafs.WalkComponentSymlink
			break
		}

		child, childStat, err := tryStepLocked(c, name, curDirFD, func(flags int) (int, error) {
			return unix.Openat(curDirFD.hostFD, name, flags, 0)
		})
		if err == unix.ENOENT {
			status = lisafs.WalkComponentDoesNotExist
			break
		}
		if err != nil {
			return 0, err
		}

		// Write inode to payloadBuf and update state.
		var childInode lisafs.Inode
		child.initInodeWithStat(&childInode, &childStat)
		childInode.MarshalUnsafe(payloadBuf[payloadPos:])
		payloadPos += childInode.SizeBytes()
		numInodes++
		curDirFD = child
	}
	cu.Release()

	// lisafs.WalkResp writes the walk status followed by the number of inodes in
	// the beginning.
	status.MarshalUnsafe(payloadBuf)
	numInodes.MarshalUnsafe(payloadBuf[status.SizeBytes():])
	return uint32(payloadPos), nil
}

// WalkStat implements lisafs.ControlFDImpl.WalkStat.
func (fd *controlFDLisa) WalkStat(c *lisafs.Connection, comm lisafs.Communicator, path lisafs.StringArray) (uint32, error) {
	// We may need to generate statx for dirFD + each component walked. We will
	// manually marshal the statx results into the payload buffer as they are
	// generated to avoid the slice allocation. The memory format should be the
	// same as lisafs.WalkStatResp's.
	var numStats primitive.Uint32
	maxPayloadSize := numStats.SizeBytes() + (len(path) * linux.SizeOfStatx)
	if maxPayloadSize > math.MaxUint32 {
		// Too much to walk, can't do.
		return 0, unix.EIO
	}
	payloadBuf := comm.PayloadBuf(uint32(maxPayloadSize))
	payloadPos := numStats.SizeBytes()

	s := c.Server()
	s.RenameMu.RLock()
	defer s.RenameMu.RUnlock()

	curDirFD := fd.hostFD
	closeCurDirFD := func() {
		if curDirFD != fd.hostFD {
			unix.Close(curDirFD)
		}
	}
	defer closeCurDirFD()
	var (
		stat     linux.Statx
		unixStat unix.Stat_t
	)
	if len(path) > 0 && len(path[0]) == 0 {
		// Write stat results for dirFD if the first path component is "".
		if err := unix.Fstat(fd.hostFD, &unixStat); err != nil {
			return 0, err
		}
		unixToLinuxStat(&unixStat, &stat)
		stat.MarshalUnsafe(payloadBuf[payloadPos:])
		payloadPos += stat.SizeBytes()
		path = path[1:]
		numStats++
	}

	// Don't attempt walking if parent is a symlink.
	if fd.IsSymlink() {
		return 0, nil
	}
	for _, name := range path {
		curFD, err := unix.Openat(curDirFD, name, unix.O_PATH|openFlags, 0)
		if err == unix.ENOENT {
			// No more path components exist on the filesystem. Return the partial
			// walk to the client.
			break
		}
		if err != nil {
			return 0, err
		}
		closeCurDirFD()
		curDirFD = curFD

		// Write stat results for curFD.
		if err := unix.Fstat(curFD, &unixStat); err != nil {
			return 0, err
		}
		unixToLinuxStat(&unixStat, &stat)
		stat.MarshalUnsafe(payloadBuf[payloadPos:])
		payloadPos += stat.SizeBytes()
		numStats++

		// Symlinks terminate walk. This client gets the symlink stat result, but
		// will have to invoke Walk again with the resolved path.
		if unixStat.Mode&unix.S_IFMT == unix.S_IFLNK {
			break
		}
	}

	// lisafs.WalkStatResp writes the number of stats in the beginning.
	numStats.MarshalUnsafe(payloadBuf)
	return uint32(payloadPos), nil
}

// Open implements lisafs.ControlFDImpl.Open.
func (fd *controlFDLisa) Open(c *lisafs.Connection, comm lisafs.Communicator, flags uint32) (uint32, error) {
	flags |= openFlags
	newHostFD, err := unix.Openat(int(procSelfFD.FD()), strconv.Itoa(fd.hostFD), int(flags)&^unix.O_NOFOLLOW, 0)
	if err != nil {
		return 0, err
	}
	newFD := fd.newOpenFDLisa(newHostFD, flags)

	if fd.IsRegular() {
		// Donate FD for regular files only. Since FD donation is a destructive
		// operation, we should duplicate the to-be-donated FD. Eat the error if
		// one occurs, it is better to have an FD without a host FD, than failing
		// the Open attempt.
		if dupFD, err := unix.Dup(newFD.hostFD); err == nil {
			_ = comm.DonateFD(dupFD)
		}
	}

	resp := lisafs.OpenAtResp{NewFD: newFD.ID()}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// OpenCreate implements lisafs.ControlFDImpl.OpenCreate.
func (fd *controlFDLisa) OpenCreate(c *lisafs.Connection, comm lisafs.Communicator, mode linux.FileMode, uid lisafs.UID, gid lisafs.GID, name string, flags uint32) (uint32, error) {
	// Need to hold rename mutex for reading while performing the walk. Also keep
	// holding it while the cleanup is still possible.
	var resp lisafs.OpenCreateAtResp
	var newFD *openFDLisa
	if err := c.Server().WithRenameReadLock(func() error {
		createFlags := unix.O_CREAT | unix.O_EXCL | unix.O_RDONLY | unix.O_NONBLOCK | openFlags
		childHostFD, err := unix.Openat(fd.hostFD, name, createFlags, uint32(mode&^linux.FileTypeMask))
		if err != nil {
			return err
		}

		childFD := newControlFDLisaLocked(c, childHostFD, fd, name, linux.ModeRegular)
		cu := cleanup.Make(func() {
			// Best effort attempt to remove the file in case of failure.
			if err := unix.Unlinkat(fd.hostFD, name, 0); err != nil {
				log.Warningf("error unlinking file %q after failure: %v", path.Join(fd.FilePathLocked(), name), err)
			}
			c.RemoveControlFDLocked(childFD.ID())
		})
		defer cu.Clean()

		// Set the owners as requested by the client.
		if err := unix.Fchownat(childFD.hostFD, "", int(uid), int(gid), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}

		// Do not use the stat result from tryOpen because the owners might have
		// changed. initInode() will stat the FD again and use fresh results.
		if err := childFD.initInode(&resp.Child); err != nil {
			return err
		}

		// Now open an FD to the newly created file with the flags requested by the client.
		flags |= openFlags
		newHostFD, err := unix.Openat(int(procSelfFD.FD()), strconv.Itoa(childFD.hostFD), int(flags)&^unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		cu.Release()

		newFD = childFD.newOpenFDLisa(newHostFD, uint32(flags))
		resp.NewFD = newFD.ID()
		return nil
	}); err != nil {
		return 0, err
	}

	// Donate FD because open(O_CREAT|O_EXCL) always creates a regular file.
	// Since FD donation is a destructive operation, we should duplicate the
	// to-be-donated FD. Eat the error if one occurs, it is better to have an FD
	// without a host FD, than failing the Open attempt.
	if dupFD, err := unix.Dup(newFD.hostFD); err == nil {
		_ = comm.DonateFD(dupFD)
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// Mkdir implements lisafs.ControlFDImpl.Mkdir.
func (fd *controlFDLisa) Mkdir(c *lisafs.Connection, comm lisafs.Communicator, mode linux.FileMode, uid lisafs.UID, gid lisafs.GID, name string) (uint32, error) {
	var resp lisafs.MkdirAtResp
	if err := c.Server().WithRenameReadLock(func() error {
		if err := unix.Mkdirat(fd.hostFD, name, uint32(mode&^linux.FileTypeMask)); err != nil {
			return err
		}
		cu := cleanup.Make(func() {
			// Best effort attempt to remove the dir in case of failure.
			if err := unix.Unlinkat(fd.hostFD, name, unix.AT_REMOVEDIR); err != nil {
				log.Warningf("error unlinking dir %q after failure: %v", path.Join(fd.FilePathLocked(), name), err)
			}
		})
		defer cu.Clean()

		// Open directory to change ownership.
		childDirFd, err := unix.Openat(fd.hostFD, name, unix.O_DIRECTORY|unix.O_RDONLY|openFlags, 0)
		if err != nil {
			return err
		}
		if err := unix.Fchownat(childDirFd, "", int(uid), int(gid), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			unix.Close(childDirFd)
			return err
		}

		childDir := newControlFDLisaLocked(c, childDirFd, fd, name, linux.ModeDirectory)
		if err := childDir.initInode(&resp.ChildDir); err != nil {
			c.RemoveControlFDLocked(childDir.ID())
			return err
		}
		cu.Release()

		return nil
	}); err != nil {
		return 0, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// Mknod implements lisafs.ControlFDImpl.Mknod.
func (fd *controlFDLisa) Mknod(c *lisafs.Connection, comm lisafs.Communicator, mode linux.FileMode, uid lisafs.UID, gid lisafs.GID, name string, minor uint32, major uint32) (uint32, error) {
	// From mknod(2) man page:
	// "EPERM: [...] if the filesystem containing pathname does not support
	// the type of node requested."
	if mode.FileType() != linux.ModeRegular {
		return 0, unix.EPERM
	}

	var resp lisafs.MknodAtResp
	if err := c.Server().WithRenameReadLock(func() error {
		if err := unix.Mknodat(fd.hostFD, name, uint32(mode), 0); err != nil {
			return err
		}
		cu := cleanup.Make(func() {
			// Best effort attempt to remove the file in case of failure.
			if err := unix.Unlinkat(fd.hostFD, name, 0); err != nil {
				log.Warningf("error unlinking file %q after failure: %v", path.Join(fd.FilePathLocked(), name), err)
			}
		})
		defer cu.Clean()

		// Open file to change ownership.
		childFD, err := unix.Openat(fd.hostFD, name, unix.O_PATH|openFlags, 0)
		if err != nil {
			return err
		}
		if err := unix.Fchownat(childFD, "", int(uid), int(gid), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			unix.Close(childFD)
			return err
		}

		child := newControlFDLisaLocked(c, childFD, fd, name, mode)
		if err := child.initInode(&resp.Child); err != nil {
			c.RemoveControlFDLocked(child.ID())
			return err
		}
		cu.Release()
		return nil
	}); err != nil {
		return 0, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// Symlink implements lisafs.ControlFDImpl.Symlink.
func (fd *controlFDLisa) Symlink(c *lisafs.Connection, comm lisafs.Communicator, name string, target string, uid lisafs.UID, gid lisafs.GID) (uint32, error) {
	var resp lisafs.SymlinkAtResp
	if err := c.Server().WithRenameReadLock(func() error {
		if err := unix.Symlinkat(target, fd.hostFD, name); err != nil {
			return err
		}
		cu := cleanup.Make(func() {
			// Best effort attempt to remove the symlink in case of failure.
			if err := unix.Unlinkat(fd.hostFD, name, 0); err != nil {
				log.Warningf("error unlinking file %q after failure: %v", path.Join(fd.FilePathLocked(), name), err)
			}
		})
		defer cu.Clean()

		// Open symlink to change ownership.
		symlinkFD, err := unix.Openat(fd.hostFD, name, unix.O_PATH|openFlags, 0)
		if err != nil {
			return err
		}
		if err := unix.Fchownat(symlinkFD, "", int(uid), int(gid), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
			unix.Close(symlinkFD)
			return err
		}

		symlink := newControlFDLisaLocked(c, symlinkFD, fd, name, linux.ModeSymlink)
		if err := symlink.initInode(&resp.Symlink); err != nil {
			c.RemoveControlFDLocked(symlink.ID())
			return err
		}
		cu.Release()
		return nil
	}); err != nil {
		return 0, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// Link implements lisafs.ControlFDImpl.Link.
func (fd *controlFDLisa) Link(c *lisafs.Connection, comm lisafs.Communicator, dir lisafs.ControlFDImpl, name string) (uint32, error) {
	var resp lisafs.LinkAtResp
	if err := c.Server().WithRenameReadLock(func() error {
		dirFD := dir.(*controlFDLisa)
		if err := unix.Linkat(fd.hostFD, "", dirFD.hostFD, name, unix.AT_EMPTY_PATH); err != nil {
			return err
		}
		cu := cleanup.Make(func() {
			// Best effort attempt to remove the hard link in case of failure.
			if err := unix.Unlinkat(dirFD.hostFD, name, 0); err != nil {
				log.Warningf("error unlinking file %q after failure: %v", path.Join(dirFD.FilePathLocked(), name), err)
			}
		})
		defer cu.Clean()

		linkFD, linkStat, err := tryStepLocked(c, name, dirFD, func(flags int) (int, error) {
			return unix.Openat(dirFD.hostFD, name, flags, 0)
		})
		if err != nil {
			return err
		}
		cu.Release()

		linkFD.initInodeWithStat(&resp.Link, &linkStat)
		return nil
	}); err != nil {
		return 0, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// StatFS implements lisafs.ControlFDImpl.StatFS.
func (fd *controlFDLisa) StatFS(c *lisafs.Connection, comm lisafs.Communicator) (uint32, error) {
	var s unix.Statfs_t
	if err := unix.Fstatfs(fd.hostFD, &s); err != nil {
		return 0, err
	}

	resp := lisafs.StatFS{
		Type:            uint64(s.Type),
		BlockSize:       s.Bsize,
		Blocks:          s.Blocks,
		BlocksFree:      s.Bfree,
		BlocksAvailable: s.Bavail,
		Files:           s.Files,
		FilesFree:       s.Ffree,
		NameLength:      uint64(s.Namelen),
	}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// Readlink implements lisafs.ControlFDImpl.Readlink.
func (fd *controlFDLisa) Readlink(c *lisafs.Connection, comm lisafs.Communicator) (uint32, error) {
	// We will manually marshal lisafs.ReadLinkAtResp, which just contains a
	// lisafs.SizedString. Let unix.Readlinkat directly write into the payload
	// buffer and manually write the string size before it.

	// This is similar to what os.Readlink does.
	const limit = primitive.Uint32(1024 * 1024)
	for linkLen := primitive.Uint32(128); linkLen < limit; linkLen *= 2 {
		b := comm.PayloadBuf(uint32(linkLen) + uint32(linkLen.SizeBytes()))
		n, err := unix.Readlinkat(fd.hostFD, "", b[linkLen.SizeBytes():])
		if err != nil {
			return 0, err
		}
		if n < int(linkLen) {
			linkLen = primitive.Uint32(n)
			linkLen.MarshalUnsafe(b[:linkLen.SizeBytes()])
			return uint32(linkLen) + uint32(linkLen.SizeBytes()), nil
		}
	}
	return 0, unix.ENOMEM
}

// Connect implements lisafs.ControlFDImpl.Connect.
func (fd *controlFDLisa) Connect(c *lisafs.Connection, comm lisafs.Communicator, sockType uint32) error {
	s := c.ServerImpl().(*LisafsServer)
	if !s.config.HostUDS {
		return unix.ECONNREFUSED
	}

	// Lock RenameMu so that the hostPath read stays valid and is not tampered
	// with until it is actually connected to.
	s.RenameMu.RLock()
	defer s.RenameMu.RUnlock()

	// TODO(gvisor.dev/issue/1003): Due to different app vs replacement
	// mappings, the app path may have fit in the sockaddr, but we can't fit
	// hostPath in our sockaddr. We'd need to redirect through a shorter path
	// in order to actually connect to this socket.
	hostPath := fd.FilePathLocked()
	if len(hostPath) > 108 { // UNIX_PATH_MAX = 108 is defined in afunix.h.
		return unix.ECONNREFUSED
	}

	// Only the following types are supported.
	switch sockType {
	case unix.SOCK_STREAM, unix.SOCK_DGRAM, unix.SOCK_SEQPACKET:
	default:
		return unix.ENXIO
	}

	sock, err := unix.Socket(unix.AF_UNIX, int(sockType), 0)
	if err != nil {
		return err
	}
	if err := comm.DonateFD(sock); err != nil {
		return err
	}

	sa := unix.SockaddrUnix{Name: hostPath}
	if err := unix.Connect(sock, &sa); err != nil {
		return err
	}
	return nil
}

// Unlink implements lisafs.ControlFDImpl.Unlink.
func (fd *controlFDLisa) Unlink(c *lisafs.Connection, name string, flags uint32) error {
	return c.Server().WithRenameReadLock(func() error {
		return unix.Unlinkat(fd.hostFD, name, int(flags))
	})
}

// RenameLocked implements lisafs.ControlFDImpl.RenameLocked.
func (fd *controlFDLisa) RenameLocked(c *lisafs.Connection, newDir lisafs.ControlFDImpl, newName string) (func(lisafs.ControlFDImpl), func(), error) {
	// Note that there is no controlFDLisa specific update needed on rename.
	return nil, nil, renameat(fd.ParentLocked().(*controlFDLisa).hostFD, fd.NameLocked(), newDir.(*controlFDLisa).hostFD, newName)
}

// GetXattr implements lisafs.ControlFDImpl.GetXattr.
func (fd *controlFDLisa) GetXattr(c *lisafs.Connection, comm lisafs.Communicator, name string, size uint32) (uint32, error) {
	if !c.ServerImpl().(*LisafsServer).config.EnableVerityXattr {
		return 0, unix.EOPNOTSUPP
	}
	if _, ok := verityXattrs[name]; !ok {
		return 0, unix.EOPNOTSUPP
	}

	// Manually marshal lisafs.FGetXattrResp to avoid allocations and copying.
	var valueLen primitive.Uint32
	buf := comm.PayloadBuf(uint32(valueLen.SizeBytes()) + size)
	n, err := unix.Fgetxattr(fd.hostFD, name, buf[valueLen.SizeBytes():])
	if err != nil {
		return 0, err
	}
	valueLen = primitive.Uint32(n)
	valueLen.MarshalBytes(buf[:valueLen.SizeBytes()])

	return uint32(valueLen.SizeBytes() + n), nil
}

// SetXattr implements lisafs.ControlFDImpl.SetXattr.
func (fd *controlFDLisa) SetXattr(c *lisafs.Connection, name string, value string, flags uint32) error {
	if !c.ServerImpl().(*LisafsServer).config.EnableVerityXattr {
		return unix.EOPNOTSUPP
	}
	if _, ok := verityXattrs[name]; !ok {
		return unix.EOPNOTSUPP
	}
	return unix.Fsetxattr(fd.hostFD, name, []byte(value) /* sigh */, int(flags))
}

// ListXattr implements lisafs.ControlFDImpl.ListXattr.
func (fd *controlFDLisa) ListXattr(c *lisafs.Connection, comm lisafs.Communicator, size uint64) (uint32, error) {
	return 0, unix.EOPNOTSUPP
}

// RemoveXattr implements lisafs.ControlFDImpl.RemoveXattr.
func (fd *controlFDLisa) RemoveXattr(c *lisafs.Connection, comm lisafs.Communicator, name string) error {
	return unix.EOPNOTSUPP
}

// openFDLisa implements lisafs.OpenFDImpl.
type openFDLisa struct {
	lisafs.OpenFD

	// hostFD is the host file descriptor which can be used to make syscalls.
	hostFD int
}

var _ lisafs.OpenFDImpl = (*openFDLisa)(nil)

func (fd *controlFDLisa) newOpenFDLisa(hostFD int, flags uint32) *openFDLisa {
	newFD := &openFDLisa{
		hostFD: hostFD,
	}
	newFD.OpenFD.Init(fd.FD(), flags, newFD)
	return newFD
}

// FD implements lisafs.OpenFDImpl.FD.
func (fd *openFDLisa) FD() *lisafs.OpenFD {
	if fd == nil {
		return nil
	}
	return &fd.OpenFD
}

// Close implements lisafs.OpenFDImpl.Close.
func (fd *openFDLisa) Close(c *lisafs.Connection) {
	if fd.hostFD >= 0 {
		_ = unix.Close(fd.hostFD)
		fd.hostFD = -1
	}
}

// Stat implements lisafs.OpenFDImpl.Stat.
func (fd *openFDLisa) Stat(c *lisafs.Connection, comm lisafs.Communicator) (uint32, error) {
	var resp linux.Statx
	if err := fstatTo(fd.hostFD, &resp); err != nil {
		return 0, err
	}

	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// Sync implements lisafs.OpenFDImpl.Sync.
func (fd *openFDLisa) Sync(c *lisafs.Connection) error {
	return unix.Fsync(fd.hostFD)
}

// Write implements lisafs.OpenFDImpl.Write.
func (fd *openFDLisa) Write(c *lisafs.Connection, comm lisafs.Communicator, buf []byte, off uint64) (uint32, error) {
	rw := rwfd.NewReadWriter(fd.hostFD)
	n, err := rw.WriteAt(buf, int64(off))
	if err != nil {
		return 0, err
	}

	resp := &lisafs.PWriteResp{Count: uint64(n)}
	respLen := uint32(resp.SizeBytes())
	resp.MarshalUnsafe(comm.PayloadBuf(respLen))
	return respLen, nil
}

// Read implements lisafs.OpenFDImpl.Read.
func (fd *openFDLisa) Read(c *lisafs.Connection, comm lisafs.Communicator, off uint64, count uint32) (uint32, error) {
	// To save an allocation and a copy, we directly read into the payload
	// buffer. The rest of the response message is manually marshalled.
	var resp lisafs.PReadResp
	respMetaSize := uint32(resp.NumBytes.SizeBytes())
	maxRespLen := respMetaSize + count

	payloadBuf := comm.PayloadBuf(maxRespLen)
	rw := rwfd.NewReadWriter(fd.hostFD)
	n, err := rw.ReadAt(payloadBuf[respMetaSize:], int64(off))
	if err != nil && err != io.EOF {
		return 0, err
	}

	// Write the response metadata onto the payload buffer. The response contents
	// already have been written immediately after it.
	resp.NumBytes = primitive.Uint32(n)
	resp.NumBytes.MarshalUnsafe(payloadBuf[:respMetaSize])
	return respMetaSize + uint32(n), nil
}

// Allocate implements lisafs.OpenFDImpl.Allocate.
func (fd *openFDLisa) Allocate(c *lisafs.Connection, mode, off, length uint64) error {
	return unix.Fallocate(fd.hostFD, uint32(mode), int64(off), int64(length))
}

// Flush implements lisafs.OpenFDImpl.Flush.
func (fd *openFDLisa) Flush(c *lisafs.Connection) error {
	return nil
}

// Getdent64 implements lisafs.OpenFDImpl.Getdent64.
func (fd *openFDLisa) Getdent64(c *lisafs.Connection, comm lisafs.Communicator, count uint32, seek0 bool) (uint32, error) {
	if seek0 {
		if _, err := unix.Seek(fd.hostFD, 0, 0); err != nil {
			return 0, err
		}
	}

	// We will manually marshal the response lisafs.Getdents64Resp.

	// numDirents is the number of dirents marshalled into the payload.
	var numDirents primitive.Uint32
	// The payload starts with numDirents, dirents go right after that.
	// payloadBufPos represents the position at which to write the next dirent.
	payloadBufPos := uint32(numDirents.SizeBytes())
	// Request enough payloadBuf for 10 dirents, we will extend when needed.
	payloadBuf := comm.PayloadBuf(payloadBufPos + 10*unixDirentMaxSize)

	var direntsBuf [8192]byte
	var bytesRead int
	for bytesRead < int(count) {
		bufEnd := len(direntsBuf)
		if remaining := int(count) - bytesRead; remaining < bufEnd {
			bufEnd = remaining
		}
		n, err := unix.Getdents(fd.hostFD, direntsBuf[:bufEnd])
		if err != nil {
			if err == unix.EINVAL && bufEnd < 268 {
				// getdents64(2) returns EINVAL is returned when the result
				// buffer is too small. If bufEnd is smaller than the max
				// size of unix.Dirent, then just break here to return all
				// dirents collected till now.
				break
			}
			return 0, err
		}
		if n <= 0 {
			break
		}
		bytesRead += n

		var statErr error
		parseDirents(direntsBuf[:n], func(ino uint64, off int64, ftype uint8, name string) bool {
			dirent := lisafs.Dirent64{
				Ino:  primitive.Uint64(ino),
				Off:  primitive.Uint64(off),
				Type: primitive.Uint8(ftype),
				Name: lisafs.SizedString(name),
			}

			// The client also wants the device ID, which annoyingly incurs an
			// additional syscall per dirent. Live with it.
			stat, err := statAt(fd.hostFD, name)
			if err != nil {
				statErr = err
				return false
			}
			dirent.DevMinor = primitive.Uint32(unix.Minor(stat.Dev))
			dirent.DevMajor = primitive.Uint32(unix.Major(stat.Dev))

			// Paste the dirent into the payload buffer without having the dirent
			// escape. Request a larger buffer if needed.
			if int(payloadBufPos)+dirent.SizeBytes() > len(payloadBuf) {
				// Ask for 10 large dirents worth of more space.
				payloadBuf = comm.PayloadBuf(payloadBufPos + 10*unixDirentMaxSize)
			}
			dirent.MarshalBytes(payloadBuf[payloadBufPos:])
			payloadBufPos += uint32(dirent.SizeBytes())
			numDirents++
			return true
		})
		if statErr != nil {
			return 0, statErr
		}
	}

	// The number of dirents goes at the beginning of the payload.
	numDirents.MarshalUnsafe(payloadBuf)
	return payloadBufPos, nil
}

// tryStepLocked tries to walk via open() with different modes as documented.
// It then initializes and returns the control FD.
//
// Precondition: server's rename mutex must at least be read locked.
func tryStepLocked(c *lisafs.Connection, name string, parent *controlFDLisa, open func(flags int) (int, error)) (*controlFDLisa, unix.Stat_t, error) {
	// Attempt to open file in the following in order:
	//   1. RDONLY | NONBLOCK: for all files, directories, ro mounts, FIFOs.
	//      Use non-blocking to prevent getting stuck inside open(2) for
	//      FIFOs. This option has no effect on regular files.
	//   2. PATH: for symlinks, sockets.
	options := []struct {
		flag     int
		readable bool
	}{
		{
			flag:     unix.O_RDONLY | unix.O_NONBLOCK,
			readable: true,
		},
		{
			flag:     unix.O_PATH,
			readable: false,
		},
	}

	for i, option := range options {
		hostFD, err := open(option.flag | openFlags)
		if err == nil {
			var stat unix.Stat_t
			if err = unix.Fstat(hostFD, &stat); err == nil {
				return newControlFDLisaLocked(c, hostFD, parent, name, linux.FileMode(stat.Mode)), stat, nil
			}
			unix.Close(hostFD)
		}

		e := extractErrno(err)
		if e == unix.ENOENT {
			// File doesn't exist, no point in retrying.
			return nil, unix.Stat_t{}, e
		}
		if i < len(options)-1 {
			continue
		}
		return nil, unix.Stat_t{}, e
	}
	panic("unreachable")
}

func fstatTo(hostFD int, stat *linux.Statx) error {
	var unixStat unix.Stat_t
	if err := unix.Fstat(hostFD, &unixStat); err != nil {
		return err
	}

	unixToLinuxStat(&unixStat, stat)
	return nil
}

func unixToLinuxStat(from *unix.Stat_t, to *linux.Statx) {
	to.Mask = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_INO | unix.STATX_NLINK | unix.STATX_UID | unix.STATX_GID | unix.STATX_SIZE | unix.STATX_BLOCKS | unix.STATX_ATIME | unix.STATX_MTIME | unix.STATX_CTIME
	to.Mode = uint16(from.Mode)
	to.DevMinor = unix.Minor(from.Dev)
	to.DevMajor = unix.Major(from.Dev)
	to.Ino = from.Ino
	to.Nlink = uint32(from.Nlink)
	to.UID = from.Uid
	to.GID = from.Gid
	to.RdevMinor = unix.Minor(from.Rdev)
	to.RdevMajor = unix.Major(from.Rdev)
	to.Size = uint64(from.Size)
	to.Blksize = uint32(from.Blksize)
	to.Blocks = uint64(from.Blocks)
	to.Atime.Sec = from.Atim.Sec
	to.Atime.Nsec = uint32(from.Atim.Nsec)
	to.Mtime.Sec = from.Mtim.Sec
	to.Mtime.Nsec = uint32(from.Mtim.Nsec)
	to.Ctime.Sec = from.Ctim.Sec
	to.Ctime.Nsec = uint32(from.Ctim.Nsec)
}
