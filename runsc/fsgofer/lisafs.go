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
	"os"
	"path"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/cleanup"
	rwfd "gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
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
	s.Server.Init(s, lisafs.ServerOpts{
		WalkStatSupported: true,
		SetAttrOnDeleted:  true,
		AllocateOnDeleted: true,
	})
	return s
}

// Mount implements lisafs.ServerImpl.Mount.
func (s *LisafsServer) Mount(c *lisafs.Connection, mountNode *lisafs.Node) (*lisafs.ControlFD, linux.Statx, error) {
	mountPath := mountNode.FilePath()
	rootHostFD, err := tryOpen(func(flags int) (int, error) {
		return unix.Open(mountPath, flags, 0)
	})
	if err != nil {
		return nil, linux.Statx{}, err
	}
	cu := cleanup.Make(func() {
		_ = unix.Close(rootHostFD)
	})
	defer cu.Clean()

	stat, err := fstatTo(rootHostFD)
	if err != nil {
		return nil, linux.Statx{}, err
	}

	if err := checkSupportedFileType(uint32(stat.Mode), &s.config); err != nil {
		log.Warningf("Mount: checkSupportedFileType() failed for file %q with mode %o: %v", mountPath, stat.Mode, err)
		return nil, linux.Statx{}, err
	}
	cu.Release()

	rootFD := &controlFDLisa{
		hostFD:         rootHostFD,
		writableHostFD: atomicbitops.FromInt32(-1),
	}
	mountNode.IncRef() // Ref is transferred to ControlFD.
	rootFD.ControlFD.Init(c, mountNode, linux.FileMode(stat.Mode), rootFD)
	return rootFD.FD(), stat, nil
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
		lisafs.BindAt,
		lisafs.Listen,
		lisafs.Accept,
	}
}

// controlFDLisa implements lisafs.ControlFDImpl.
type controlFDLisa struct {
	lisafs.ControlFD

	// hostFD is the file descriptor which can be used to make host syscalls.
	hostFD int

	// writableHostFD is the file descriptor number for a writable FD opened on
	// the same FD as `hostFD`. It is initialized to -1, and can change in value
	// exactly once.
	writableHostFD atomicbitops.Int32
}

var _ lisafs.ControlFDImpl = (*controlFDLisa)(nil)

func newControlFDLisa(hostFD int, parent *controlFDLisa, name string, mode linux.FileMode) *controlFDLisa {
	var (
		childFD    *controlFDLisa
		childNode  *lisafs.Node
		parentNode = parent.Node()
	)
	parentNode.WithChildrenMu(func() {
		childNode = parentNode.LookupChildLocked(name)
		if childNode == nil {
			// Common case. Performance hack which is used to allocate the node and
			// its control FD together in the heap. For a well-behaving client, there
			// will be a 1:1 mapping between control FD and node and their lifecycle
			// will be similar too. This will help reduce allocations and memory
			// fragmentation. This is more cache friendly too.
			temp := struct {
				node lisafs.Node
				fd   controlFDLisa
			}{}
			childFD = &temp.fd
			childNode = &temp.node
			childNode.InitLocked(name, parentNode)
		} else {
			childNode.IncRef()
			childFD = &controlFDLisa{}
		}
	})
	childFD.hostFD = hostFD
	childFD.writableHostFD = atomicbitops.FromInt32(-1)
	childFD.ControlFD.Init(parent.Conn(), childNode, mode, childFD)
	return childFD
}

func (fd *controlFDLisa) getWritableFD() (int, error) {
	if writableFD := fd.writableHostFD.Load(); writableFD != -1 {
		return int(writableFD), nil
	}

	writableFD, err := unix.Openat(int(procSelfFD.FD()), strconv.Itoa(fd.hostFD), (unix.O_WRONLY|openFlags)&^unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	if !fd.writableHostFD.CompareAndSwap(-1, int32(writableFD)) {
		// Race detected, use the new value and clean this up.
		unix.Close(writableFD)
		return int(fd.writableHostFD.Load()), nil
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
func (fd *controlFDLisa) Close() {
	if fd.hostFD >= 0 {
		_ = unix.Close(fd.hostFD)
		fd.hostFD = -1
	}
	// No concurrent access is possible so no need to use atomics.
	if fd.writableHostFD.RacyLoad() >= 0 {
		_ = unix.Close(int(fd.writableHostFD.RacyLoad()))
		fd.writableHostFD = atomicbitops.FromInt32(-1)
	}
}

// Stat implements lisafs.ControlFDImpl.Stat.
func (fd *controlFDLisa) Stat() (linux.Statx, error) {
	return fstatTo(fd.hostFD)
}

// SetStat implements lisafs.ControlFDImpl.SetStat.
func (fd *controlFDLisa) SetStat(stat lisafs.SetStatReq) (failureMask uint32, failureErr error) {
	if stat.Mask&unix.STATX_MODE != 0 {
		if fd.IsSocket() {
			// fchmod(2) on socket files created via bind(2) fails. We need to
			// fchmodat(2) it from its parent.
			sockPath := fd.Node().FilePath()
			parent, err := unix.Open(path.Dir(sockPath), openFlags|unix.O_PATH, 0)
			if err == nil {
				// Note that AT_SYMLINK_NOFOLLOW flag is not currently supported.
				err = unix.Fchmodat(parent, path.Base(sockPath), stat.Mode&^unix.S_IFMT, 0 /* flags */)
				unix.Close(parent)
			}
			if err != nil {
				log.Warningf("SetStat fchmod failed on socket %q, err: %v", sockPath, err)
				failureMask |= unix.STATX_MODE
				failureErr = err
			}
		} else {
			if err := unix.Fchmod(fd.hostFD, stat.Mode&^unix.S_IFMT); err != nil {
				log.Warningf("SetStat fchmod failed %q, err: %v", fd.Node().FilePath(), err)
				failureMask |= unix.STATX_MODE
				failureErr = err
			}
		}
	}

	if stat.Mask&unix.STATX_SIZE != 0 {
		// ftruncate(2) requires the FD to be open for writing.
		writableFD, err := fd.getWritableFD()
		if err == nil {
			err = unix.Ftruncate(writableFD, int64(stat.Size))
		}
		if err != nil {
			log.Warningf("SetStat ftruncate failed %q, err: %v", fd.Node().FilePath(), err)
			failureMask |= unix.STATX_SIZE
			failureErr = err
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
			// name. We need the parent FD.
			symlinkPath := fd.Node().FilePath()
			parent, err := unix.Open(path.Dir(symlinkPath), openFlags|unix.O_PATH, 0)
			if err == nil {
				err = utimensat(parent, path.Base(symlinkPath), utimes, unix.AT_SYMLINK_NOFOLLOW)
				unix.Close(parent)
			}
			if err != nil {
				failureMask |= (stat.Mask & (unix.STATX_ATIME | unix.STATX_MTIME))
				failureErr = err
			}
		} else {
			hostFD := fd.hostFD
			if fd.IsRegular() {
				// For regular files, utimensat(2) requires the FD to be open for
				// writing, see BUGS section.
				if writableFD, err := fd.getWritableFD(); err == nil {
					hostFD = writableFD
				} else {
					log.Warningf("SetStat getWritableFD failed %q, err: %v", fd.Node().FilePath(), err)
				}
			}
			// Directories and regular files can operate directly on the fd
			// using empty name.
			err := utimensat(hostFD, "", utimes, 0)
			if err != nil {
				log.Warningf("SetStat utimens failed %q, err: %v", fd.Node().FilePath(), err)
				failureMask |= (stat.Mask & (unix.STATX_ATIME | unix.STATX_MTIME))
				failureErr = err
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
			log.Warningf("SetStat fchown failed %q, err: %v", fd.Node().FilePath(), err)
			failureMask |= stat.Mask & (unix.STATX_UID | unix.STATX_GID)
			failureErr = err
		}
	}

	return
}

// Walk implements lisafs.ControlFDImpl.Walk.
func (fd *controlFDLisa) Walk(name string) (*lisafs.ControlFD, linux.Statx, error) {
	childHostFD, err := tryOpen(func(flags int) (int, error) {
		return unix.Openat(fd.hostFD, name, flags, 0)
	})
	if err != nil {
		return nil, linux.Statx{}, err
	}

	stat, err := fstatTo(childHostFD)
	if err != nil {
		_ = unix.Close(childHostFD)
		return nil, linux.Statx{}, err
	}

	if err := checkSupportedFileType(uint32(stat.Mode), &fd.Conn().ServerImpl().(*LisafsServer).config); err != nil {
		_ = unix.Close(childHostFD)
		log.Warningf("Walk: checkSupportedFileType() failed for %q with mode %o: %v", name, stat.Mode, err)
		return nil, linux.Statx{}, err
	}

	return newControlFDLisa(childHostFD, fd, name, linux.FileMode(stat.Mode)).FD(), stat, nil
}

// WalkStat implements lisafs.ControlFDImpl.WalkStat.
func (fd *controlFDLisa) WalkStat(path lisafs.StringArray, recordStat func(linux.Statx)) error {
	// Note that while performing the walk below, we do not have read concurrency
	// guarantee for any descendants. So files can be created/deleted inside fd
	// while the walk is being performed. However, this should be fine from a
	// security perspective as we are using host FDs to walk and checking that
	// each opened path component is not a symlink.
	curDirFD := fd.hostFD
	closeCurDirFD := func() {
		if curDirFD != fd.hostFD {
			unix.Close(curDirFD)
		}
	}
	defer closeCurDirFD()
	if len(path) > 0 && len(path[0]) == 0 {
		// Write stat results for dirFD if the first path component is "".
		stat, err := fstatTo(fd.hostFD)
		if err != nil {
			return err
		}
		recordStat(stat)
		path = path[1:]
	}

	// Don't attempt walking if parent is a symlink.
	if fd.IsSymlink() {
		return nil
	}
	server := fd.Conn().ServerImpl().(*LisafsServer)
	for _, name := range path {
		curFD, err := unix.Openat(curDirFD, name, unix.O_PATH|openFlags, 0)
		if err == unix.ENOENT {
			// No more path components exist on the filesystem. Return the partial
			// walk to the client.
			break
		}
		if err != nil {
			return err
		}
		closeCurDirFD()
		curDirFD = curFD

		stat, err := fstatTo(curFD)
		if err != nil {
			return err
		}
		if err := checkSupportedFileType(uint32(stat.Mode), &server.config); err != nil {
			log.Warningf("WalkStat: checkSupportedFileType() failed for file %q with mode %o while walking path %+v: %v", name, stat.Mode, path, err)
			return err
		}
		recordStat(stat)

		// Symlinks terminate walk. This client gets the symlink stat result, but
		// will have to invoke Walk again with the resolved path.
		if stat.Mode&unix.S_IFMT == unix.S_IFLNK {
			break
		}
	}

	return nil
}

// Open implements lisafs.ControlFDImpl.Open.
func (fd *controlFDLisa) Open(flags uint32) (*lisafs.OpenFD, int, error) {
	flags |= openFlags
	newHostFD, err := unix.Openat(int(procSelfFD.FD()), strconv.Itoa(fd.hostFD), int(flags)&^unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, -1, err
	}
	openFD := fd.newOpenFDLisa(newHostFD, flags)

	hostOpenFD := -1
	switch fd.FileType() {
	case unix.S_IFREG:
		// Best effort to donate file to the Sentry (for performance only).
		hostOpenFD, _ = unix.Dup(openFD.hostFD)

	case unix.S_IFIFO, unix.S_IFCHR:
		// Character devices and pipes can block indefinitely during reads/writes,
		// which is not allowed for gofer operations. Ensure that it donates an FD
		// back to the caller, so it can wait on the FD when reads/writes return
		// EWOULDBLOCK.
		var err error
		hostOpenFD, err = unix.Dup(openFD.hostFD)
		if err != nil {
			return nil, 0, err
		}
	}

	return openFD.FD(), hostOpenFD, nil
}

// OpenCreate implements lisafs.ControlFDImpl.OpenCreate.
func (fd *controlFDLisa) OpenCreate(mode linux.FileMode, uid lisafs.UID, gid lisafs.GID, name string, flags uint32) (*lisafs.ControlFD, linux.Statx, *lisafs.OpenFD, int, error) {
	createFlags := unix.O_CREAT | unix.O_EXCL | unix.O_RDONLY | unix.O_NONBLOCK | openFlags
	childHostFD, err := unix.Openat(fd.hostFD, name, createFlags, uint32(mode&^linux.FileTypeMask))
	if err != nil {
		return nil, linux.Statx{}, nil, -1, err
	}

	cu := cleanup.Make(func() {
		// Best effort attempt to remove the file in case of failure.
		if err := unix.Unlinkat(fd.hostFD, name, 0); err != nil {
			log.Warningf("error unlinking file %q after failure: %v", path.Join(fd.Node().FilePath(), name), err)
		}
		unix.Close(childHostFD)
	})
	defer cu.Clean()

	// Set the owners as requested by the client.
	if err := unix.Fchownat(childHostFD, "", int(uid), int(gid), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, linux.Statx{}, nil, -1, err
	}

	// Get stat results.
	childStat, err := fstatTo(childHostFD)
	if err != nil {
		return nil, linux.Statx{}, nil, -1, err
	}

	// Now open an FD to the newly created file with the flags requested by the client.
	flags |= openFlags
	newHostFD, err := unix.Openat(int(procSelfFD.FD()), strconv.Itoa(childHostFD), int(flags)&^unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, linux.Statx{}, nil, -1, err
	}
	cu.Release()

	childFD := newControlFDLisa(childHostFD, fd, name, linux.ModeRegular)
	newFD := childFD.newOpenFDLisa(newHostFD, uint32(flags))

	// Donate FD because open(O_CREAT|O_EXCL) always creates a regular file.
	// Since FD donation is a destructive operation, we should duplicate the
	// to-be-donated FD. Eat the error if one occurs, it is better to have an FD
	// without a host FD, than failing the Open attempt.
	hostOpenFD := -1
	if dupFD, err := unix.Dup(newFD.hostFD); err == nil {
		hostOpenFD = dupFD
	}

	return childFD.FD(), childStat, newFD.FD(), hostOpenFD, nil
}

// Mkdir implements lisafs.ControlFDImpl.Mkdir.
func (fd *controlFDLisa) Mkdir(mode linux.FileMode, uid lisafs.UID, gid lisafs.GID, name string) (*lisafs.ControlFD, linux.Statx, error) {
	if err := unix.Mkdirat(fd.hostFD, name, uint32(mode&^linux.FileTypeMask)); err != nil {
		return nil, linux.Statx{}, err
	}
	cu := cleanup.Make(func() {
		// Best effort attempt to remove the dir in case of failure.
		if err := unix.Unlinkat(fd.hostFD, name, unix.AT_REMOVEDIR); err != nil {
			log.Warningf("error unlinking dir %q after failure: %v", path.Join(fd.Node().FilePath(), name), err)
		}
	})
	defer cu.Clean()

	// Open directory to change ownership.
	childDirFd, err := tryOpen(func(flags int) (int, error) {
		return unix.Openat(fd.hostFD, name, flags|unix.O_DIRECTORY, 0)
	})
	if err != nil {
		return nil, linux.Statx{}, err
	}
	if err := unix.Fchownat(childDirFd, "", int(uid), int(gid), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		unix.Close(childDirFd)
		return nil, linux.Statx{}, err
	}

	// Get stat results.
	childDirStat, err := fstatTo(childDirFd)
	if err != nil {
		unix.Close(childDirFd)
		return nil, linux.Statx{}, err
	}

	cu.Release()
	return newControlFDLisa(childDirFd, fd, name, linux.ModeDirectory).FD(), childDirStat, nil
}

// Mknod implements lisafs.ControlFDImpl.Mknod.
func (fd *controlFDLisa) Mknod(mode linux.FileMode, uid lisafs.UID, gid lisafs.GID, name string, minor uint32, major uint32) (*lisafs.ControlFD, linux.Statx, error) {
	// From mknod(2) man page:
	// "EPERM: [...] if the filesystem containing pathname does not support
	// the type of node requested."
	if mode.FileType() != linux.ModeRegular {
		return nil, linux.Statx{}, unix.EPERM
	}

	if err := unix.Mknodat(fd.hostFD, name, uint32(mode), 0); err != nil {
		return nil, linux.Statx{}, err
	}
	cu := cleanup.Make(func() {
		// Best effort attempt to remove the file in case of failure.
		if err := unix.Unlinkat(fd.hostFD, name, 0); err != nil {
			log.Warningf("error unlinking file %q after failure: %v", path.Join(fd.Node().FilePath(), name), err)
		}
	})
	defer cu.Clean()

	// Open file to change ownership.
	childFD, err := tryOpen(func(flags int) (int, error) {
		return unix.Openat(fd.hostFD, name, flags, 0)
	})
	if err != nil {
		return nil, linux.Statx{}, err
	}
	if err := unix.Fchownat(childFD, "", int(uid), int(gid), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		unix.Close(childFD)
		return nil, linux.Statx{}, err
	}

	// Get stat results.
	childStat, err := fstatTo(childFD)
	if err != nil {
		unix.Close(childFD)
		return nil, linux.Statx{}, err
	}
	cu.Release()

	return newControlFDLisa(childFD, fd, name, mode).FD(), childStat, nil
}

// Symlink implements lisafs.ControlFDImpl.Symlink.
func (fd *controlFDLisa) Symlink(name string, target string, uid lisafs.UID, gid lisafs.GID) (*lisafs.ControlFD, linux.Statx, error) {
	if err := unix.Symlinkat(target, fd.hostFD, name); err != nil {
		return nil, linux.Statx{}, err
	}
	cu := cleanup.Make(func() {
		// Best effort attempt to remove the symlink in case of failure.
		if err := unix.Unlinkat(fd.hostFD, name, 0); err != nil {
			log.Warningf("error unlinking file %q after failure: %v", path.Join(fd.Node().FilePath(), name), err)
		}
	})
	defer cu.Clean()

	// Open symlink to change ownership.
	symlinkFD, err := unix.Openat(fd.hostFD, name, unix.O_PATH|openFlags, 0)
	if err != nil {
		return nil, linux.Statx{}, err
	}
	if err := unix.Fchownat(symlinkFD, "", int(uid), int(gid), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		unix.Close(symlinkFD)
		return nil, linux.Statx{}, err
	}

	symlinkStat, err := fstatTo(symlinkFD)
	if err != nil {
		unix.Close(symlinkFD)
		return nil, linux.Statx{}, err
	}
	cu.Release()
	return newControlFDLisa(symlinkFD, fd, name, linux.ModeSymlink).FD(), symlinkStat, nil
}

// Link implements lisafs.ControlFDImpl.Link.
func (fd *controlFDLisa) Link(dir lisafs.ControlFDImpl, name string) (*lisafs.ControlFD, linux.Statx, error) {
	dirFD := dir.(*controlFDLisa)
	if err := unix.Linkat(fd.hostFD, "", dirFD.hostFD, name, unix.AT_EMPTY_PATH); err != nil {
		return nil, linux.Statx{}, err
	}
	cu := cleanup.Make(func() {
		// Best effort attempt to remove the hard link in case of failure.
		if err := unix.Unlinkat(dirFD.hostFD, name, 0); err != nil {
			log.Warningf("error unlinking file %q after failure: %v", path.Join(dirFD.Node().FilePath(), name), err)
		}
	})
	defer cu.Clean()

	linkFD, err := tryOpen(func(flags int) (int, error) {
		return unix.Openat(dirFD.hostFD, name, flags, 0)
	})
	if err != nil {
		return nil, linux.Statx{}, err
	}

	linkStat, err := fstatTo(linkFD)
	if err != nil {
		return nil, linux.Statx{}, err
	}
	cu.Release()
	return newControlFDLisa(linkFD, dirFD, name, linux.FileMode(linkStat.Mode)).FD(), linkStat, nil
}

// StatFS implements lisafs.ControlFDImpl.StatFS.
func (fd *controlFDLisa) StatFS() (lisafs.StatFS, error) {
	var s unix.Statfs_t
	if err := unix.Fstatfs(fd.hostFD, &s); err != nil {
		return lisafs.StatFS{}, err
	}

	return lisafs.StatFS{
		Type:            uint64(s.Type),
		BlockSize:       s.Bsize,
		Blocks:          s.Blocks,
		BlocksFree:      s.Bfree,
		BlocksAvailable: s.Bavail,
		Files:           s.Files,
		FilesFree:       s.Ffree,
		NameLength:      uint64(s.Namelen),
	}, nil
}

// Readlink implements lisafs.ControlFDImpl.Readlink.
func (fd *controlFDLisa) Readlink(getLinkBuf func(uint32) []byte) (uint16, error) {
	// This is similar to what os.Readlink does.
	for linkLen := 128; linkLen < math.MaxUint16; linkLen *= 2 {
		b := getLinkBuf(uint32(linkLen))
		n, err := unix.Readlinkat(fd.hostFD, "", b)
		if err != nil {
			return 0, err
		}
		if n < int(linkLen) {
			return uint16(n), nil
		}
	}
	return 0, unix.ENOMEM
}

func isSockTypeSupported(sockType uint32) bool {
	switch sockType {
	case unix.SOCK_STREAM, unix.SOCK_DGRAM, unix.SOCK_SEQPACKET:
		return true
	default:
		log.Debugf("socket type %d is not supported", sockType)
		return false
	}
}

// Connect implements lisafs.ControlFDImpl.Connect.
func (fd *controlFDLisa) Connect(sockType uint32) (int, error) {
	if !fd.Conn().ServerImpl().(*LisafsServer).config.HostUDS.AllowOpen() {
		return -1, unix.EPERM
	}

	// TODO(gvisor.dev/issue/1003): Due to different app vs replacement
	// mappings, the app path may have fit in the sockaddr, but we can't fit
	// hostPath in our sockaddr. We'd need to redirect through a shorter path
	// in order to actually connect to this socket.
	hostPath := fd.Node().FilePath()
	if len(hostPath) >= unixPathMax {
		return -1, unix.EINVAL
	}

	if !isSockTypeSupported(sockType) {
		return -1, unix.ENXIO
	}

	sock, err := unix.Socket(unix.AF_UNIX, int(sockType), 0)
	if err != nil {
		return -1, err
	}

	sa := unix.SockaddrUnix{Name: hostPath}
	if err := unix.Connect(sock, &sa); err != nil {
		unix.Close(sock)
		return -1, err
	}
	return sock, nil
}

// BindAt implements lisafs.ControlFDImpl.BindAt.
func (fd *controlFDLisa) BindAt(name string, sockType uint32, mode linux.FileMode, uid lisafs.UID, gid lisafs.GID) (*lisafs.ControlFD, linux.Statx, *lisafs.BoundSocketFD, int, error) {
	if !fd.Conn().ServerImpl().(*LisafsServer).config.HostUDS.AllowCreate() {
		return nil, linux.Statx{}, nil, -1, unix.EPERM
	}

	// Because there is no "bindat" syscall in Linux, we must create an
	// absolute path to the socket we are creating,
	socketPath := filepath.Join(fd.Node().FilePath(), name)

	// TODO(gvisor.dev/issue/1003): Due to different app vs replacement
	// mappings, the app path may have fit in the sockaddr, but we can't fit
	// hostPath in our sockaddr. We'd need to redirect through a shorter path
	// in order to actually connect to this socket.
	if len(socketPath) >= unixPathMax {
		log.Warningf("BindAt called with name too long: %q (len=%d)", socketPath, len(socketPath))
		return nil, linux.Statx{}, nil, -1, unix.EINVAL
	}

	// Only the following types are supported.
	if !isSockTypeSupported(sockType) {
		return nil, linux.Statx{}, nil, -1, unix.ENXIO
	}

	// Create and bind the socket using the sockPath which may be a
	// symlink.
	sockFD, err := unix.Socket(unix.AF_UNIX, int(sockType), 0)
	if err != nil {
		return nil, linux.Statx{}, nil, -1, err
	}
	cu := cleanup.Make(func() {
		_ = unix.Close(sockFD)
	})
	defer cu.Clean()

	// fchmod(2) has to happen *before* the bind(2). sockFD's file mode will
	// be used in creating the filesystem-object in bind(2).
	if err := unix.Fchmod(sockFD, uint32(mode&^linux.FileTypeMask)); err != nil {
		return nil, linux.Statx{}, nil, -1, err
	}

	if err := unix.Bind(sockFD, &unix.SockaddrUnix{Name: socketPath}); err != nil {
		return nil, linux.Statx{}, nil, -1, err
	}
	cu.Add(func() {
		_ = unix.Unlink(socketPath)
	})

	sockFileFD, err := tryOpen(func(flags int) (int, error) {
		return unix.Openat(fd.hostFD, name, flags, 0)
	})
	if err != nil {
		return nil, linux.Statx{}, nil, -1, err
	}
	cu.Add(func() {
		_ = unix.Close(sockFileFD)
	})

	if err := unix.Fchownat(sockFileFD, "", int(uid), int(gid), unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, linux.Statx{}, nil, -1, err
	}

	// Stat the socket.
	sockStat, err := fstatTo(sockFileFD)
	if err != nil {
		return nil, linux.Statx{}, nil, -1, err
	}

	// Create an FD that will be donated to the sandbox.
	sockFDToDonate, err := unix.Dup(sockFD)
	if err != nil {
		return nil, linux.Statx{}, nil, -1, err
	}
	cu.Release()

	socketControlFD := newControlFDLisa(sockFD, fd, name, linux.ModeSocket)
	boundSocketFD := &boundSocketFDLisa{
		sock: os.NewFile(uintptr(sockFD), socketPath),
	}
	boundSocketFD.Init(socketControlFD.FD(), boundSocketFD)

	return socketControlFD.FD(), sockStat, boundSocketFD.FD(), sockFDToDonate, nil
}

// Unlink implements lisafs.ControlFDImpl.Unlink.
func (fd *controlFDLisa) Unlink(name string, flags uint32) error {
	return unix.Unlinkat(fd.hostFD, name, int(flags))
}

// RenameAt implements lisafs.ControlFDImpl.RenameAt.
func (fd *controlFDLisa) RenameAt(oldName string, newDir lisafs.ControlFDImpl, newName string) error {
	return renameat(fd.hostFD, oldName, newDir.(*controlFDLisa).hostFD, newName)
}

// Renamed implements lisafs.ControlFDImpl.Renamed.
func (fd *controlFDLisa) Renamed() {
	// controlFDLisa does not have any state to update on rename.
}

// GetXattr implements lisafs.ControlFDImpl.GetXattr.
func (fd *controlFDLisa) GetXattr(name string, size uint32, getValueBuf func(uint32) []byte) (uint16, error) {
	return 0, unix.EOPNOTSUPP
}

// SetXattr implements lisafs.ControlFDImpl.SetXattr.
func (fd *controlFDLisa) SetXattr(name string, value string, flags uint32) error {
	return unix.EOPNOTSUPP
}

// ListXattr implements lisafs.ControlFDImpl.ListXattr.
func (fd *controlFDLisa) ListXattr(size uint64) (lisafs.StringArray, error) {
	return nil, unix.EOPNOTSUPP
}

// RemoveXattr implements lisafs.ControlFDImpl.RemoveXattr.
func (fd *controlFDLisa) RemoveXattr(name string) error {
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
func (fd *openFDLisa) Close() {
	if fd.hostFD >= 0 {
		_ = unix.Close(fd.hostFD)
		fd.hostFD = -1
	}
}

// Stat implements lisafs.OpenFDImpl.Stat.
func (fd *openFDLisa) Stat() (linux.Statx, error) {
	return fstatTo(fd.hostFD)
}

// Sync implements lisafs.OpenFDImpl.Sync.
func (fd *openFDLisa) Sync() error {
	return unix.Fsync(fd.hostFD)
}

// Write implements lisafs.OpenFDImpl.Write.
func (fd *openFDLisa) Write(buf []byte, off uint64) (uint64, error) {
	rw := rwfd.NewReadWriter(fd.hostFD)
	n, err := rw.WriteAt(buf, int64(off))
	return uint64(n), err
}

// Read implements lisafs.OpenFDImpl.Read.
func (fd *openFDLisa) Read(buf []byte, off uint64) (uint64, error) {
	rw := rwfd.NewReadWriter(fd.hostFD)
	n, err := rw.ReadAt(buf, int64(off))
	if err != nil && err != io.EOF {
		return 0, err
	}
	return uint64(n), nil
}

// Allocate implements lisafs.OpenFDImpl.Allocate.
func (fd *openFDLisa) Allocate(mode, off, length uint64) error {
	return unix.Fallocate(fd.hostFD, uint32(mode), int64(off), int64(length))
}

// Flush implements lisafs.OpenFDImpl.Flush.
func (fd *openFDLisa) Flush() error {
	return nil
}

// Getdent64 implements lisafs.OpenFDImpl.Getdent64.
func (fd *openFDLisa) Getdent64(count uint32, seek0 bool, recordDirent func(lisafs.Dirent64)) error {
	if seek0 {
		if _, err := unix.Seek(fd.hostFD, 0, 0); err != nil {
			return err
		}
	}

	var direntsBuf [8192]byte
	var bytesRead int
	for bytesRead < int(count) {
		bufEnd := len(direntsBuf)
		if remaining := int(count) - bytesRead; remaining < bufEnd {
			bufEnd = remaining
		}
		n, err := unix.Getdents(fd.hostFD, direntsBuf[:bufEnd])
		if err != nil {
			if err == unix.EINVAL && bufEnd < unixDirentMaxSize {
				// getdents64(2) returns EINVAL is returned when the result
				// buffer is too small. If bufEnd is smaller than the max
				// size of unix.Dirent, then just break here to return all
				// dirents collected till now.
				break
			}
			return err
		}
		if n <= 0 {
			break
		}

		parseDirents(direntsBuf[:n], func(ino uint64, off int64, ftype uint8, name string, reclen uint16) bool {
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
				log.Warningf("Getdent64: skipping file %q with failed stat, err: %v", path.Join(fd.ControlFD().FD().Node().FilePath(), name), err)
				return true
			}
			dirent.DevMinor = primitive.Uint32(unix.Minor(stat.Dev))
			dirent.DevMajor = primitive.Uint32(unix.Major(stat.Dev))
			recordDirent(dirent)
			bytesRead += int(reclen)
			return true
		})
	}
	return nil
}

// Renamed implements lisafs.OpenFDImpl.Renamed.
func (fd *openFDLisa) Renamed() {
	// openFDLisa does not have any state to update on rename.
}

type boundSocketFDLisa struct {
	lisafs.BoundSocketFD

	sock *os.File
}

var _ lisafs.BoundSocketFDImpl = (*boundSocketFDLisa)(nil)

// Close implements lisafs.BoundSocketFD.Close.
func (fd *boundSocketFDLisa) Close() {
	fd.sock.Close()
}

// FD implements lisafs.BoundSocketFD.FD.
func (fd *boundSocketFDLisa) FD() *lisafs.BoundSocketFD {
	if fd == nil {
		return nil
	}
	return &fd.BoundSocketFD
}

// Listen implements lisafs.BoundSocketFD.Listen.
func (fd *boundSocketFDLisa) Listen(backlog int32) error {
	return unix.Listen(int(fd.sock.Fd()), int(backlog))
}

// Listen implements lisafs.BoundSocketFD.Accept.
func (fd *boundSocketFDLisa) Accept() (int, string, error) {
	flags := unix.O_NONBLOCK | unix.O_CLOEXEC
	nfd, _, err := unix.Accept4(int(fd.sock.Fd()), flags)
	if err != nil {
		return -1, "", err
	}
	// Return an empty peer address so that we don't leak the actual host
	// address.
	return nfd, "", err
}

// tryOpen tries to open() with different modes as documented.
func tryOpen(open func(int) (int, error)) (hostFD int, err error) {
	// Attempt to open file in the following in order:
	//   1. RDONLY | NONBLOCK: for all files, directories, ro mounts, FIFOs.
	//      Use non-blocking to prevent getting stuck inside open(2) for
	//      FIFOs. This option has no effect on regular files.
	//   2. PATH: for symlinks, sockets.
	flags := []int{
		unix.O_RDONLY | unix.O_NONBLOCK,
		unix.O_PATH,
	}

	for _, flag := range flags {
		hostFD, err = open(flag | openFlags)
		if err == nil {
			return
		}

		if e := extractErrno(err); e == unix.ENOENT {
			// File doesn't exist, no point in retrying.
			return -1, e
		}
	}
	return
}

func fstatTo(hostFD int) (linux.Statx, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(hostFD, &stat); err != nil {
		return linux.Statx{}, err
	}

	return linux.Statx{
		Mask:      unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_INO | unix.STATX_NLINK | unix.STATX_UID | unix.STATX_GID | unix.STATX_SIZE | unix.STATX_BLOCKS | unix.STATX_ATIME | unix.STATX_MTIME | unix.STATX_CTIME,
		Mode:      uint16(stat.Mode),
		DevMinor:  unix.Minor(stat.Dev),
		DevMajor:  unix.Major(stat.Dev),
		Ino:       stat.Ino,
		Nlink:     uint32(stat.Nlink),
		UID:       stat.Uid,
		GID:       stat.Gid,
		RdevMinor: unix.Minor(stat.Rdev),
		RdevMajor: unix.Major(stat.Rdev),
		Size:      uint64(stat.Size),
		Blksize:   uint32(stat.Blksize),
		Blocks:    uint64(stat.Blocks),
		Atime: linux.StatxTimestamp{
			Sec:  stat.Atim.Sec,
			Nsec: uint32(stat.Atim.Nsec),
		},
		Mtime: linux.StatxTimestamp{
			Sec:  stat.Mtim.Sec,
			Nsec: uint32(stat.Mtim.Nsec),
		},
		Ctime: linux.StatxTimestamp{
			Sec:  stat.Ctim.Sec,
			Nsec: uint32(stat.Ctim.Nsec),
		},
	}, nil
}
