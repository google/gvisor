// Copyright 2018 Google LLC
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

package host

import (
	"os"
	"path"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/device"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

func open(parent *inodeOperations, name string) (int, error) {
	if parent == nil && !path.IsAbs(name) {
		return -1, syserror.EINVAL
	}
	name = path.Clean(name)

	// Don't follow through symlinks.
	flags := syscall.O_NOFOLLOW

	if fd, err := openAt(parent, name, flags|syscall.O_RDWR, 0); err == nil {
		return fd, nil
	}
	// Retry as read-only.
	if fd, err := openAt(parent, name, flags|syscall.O_RDONLY, 0); err == nil {
		return fd, nil
	}

	// Retry as write-only.
	if fd, err := openAt(parent, name, flags|syscall.O_WRONLY, 0); err == nil {
		return fd, nil
	}

	// Retry as a symlink, by including O_PATH as an option.
	fd, err := openAt(parent, name, linux.O_PATH|flags, 0)
	if err == nil {
		return fd, nil
	}

	// Everything failed.
	return -1, err
}

func openAt(parent *inodeOperations, name string, flags int, perm linux.FileMode) (int, error) {
	if parent == nil {
		return syscall.Open(name, flags, uint32(perm))
	}
	return syscall.Openat(parent.fileState.FD(), name, flags, uint32(perm))
}

func nodeType(s *syscall.Stat_t) fs.InodeType {
	switch x := (s.Mode & syscall.S_IFMT); x {
	case syscall.S_IFLNK:
		return fs.Symlink
	case syscall.S_IFIFO:
		return fs.Pipe
	case syscall.S_IFCHR:
		return fs.CharacterDevice
	case syscall.S_IFBLK:
		return fs.BlockDevice
	case syscall.S_IFSOCK:
		return fs.Socket
	case syscall.S_IFDIR:
		return fs.Directory
	case syscall.S_IFREG:
		return fs.RegularFile
	default:
		// This shouldn't happen, but just in case...
		log.Warningf("unknown host file type %d: assuming regular", x)
		return fs.RegularFile
	}
}

func wouldBlock(s *syscall.Stat_t) bool {
	typ := nodeType(s)
	return typ == fs.Pipe || typ == fs.Socket || typ == fs.CharacterDevice
}

func stableAttr(s *syscall.Stat_t) fs.StableAttr {
	return fs.StableAttr{
		Type:     nodeType(s),
		DeviceID: hostFileDevice.DeviceID(),
		InodeID: hostFileDevice.Map(device.MultiDeviceKey{
			Device: s.Dev,
			Inode:  s.Ino,
		}),
		BlockSize: int64(s.Blksize),
	}
}

func owner(mo *superOperations, s *syscall.Stat_t) fs.FileOwner {
	// User requested no translation, just return actual owner.
	if mo.dontTranslateOwnership {
		return fs.FileOwner{auth.KUID(s.Uid), auth.KGID(s.Gid)}
	}

	// Show only IDs relevant to the sandboxed task. I.e. if we not own the
	// file, no sandboxed task can own the file. In that case, we
	// use OverflowID for UID, implying that the IDs are not mapped in the
	// "root" user namespace.
	//
	// E.g.
	// sandbox's host EUID/EGID is 1/1.
	// some_dir's host UID/GID is 2/1.
	// Task that mounted this fs has virtualized EUID/EGID 5/5.
	//
	// If you executed `ls -n` in the sandboxed task, it would show:
	// drwxwrxwrx [...] 65534 5 [...] some_dir

	// Files are owned by OverflowID by default.
	owner := fs.FileOwner{auth.KUID(auth.OverflowUID), auth.KGID(auth.OverflowGID)}

	// If we own file on host, let mounting task's initial EUID own
	// the file.
	if s.Uid == hostUID {
		owner.UID = mo.mounter.UID
	}

	// If our group matches file's group, make file's group match
	// the mounting task's initial EGID.
	for _, gid := range hostGIDs {
		if s.Gid == gid {
			owner.GID = mo.mounter.GID
			break
		}
	}
	return owner
}

func unstableAttr(mo *superOperations, s *syscall.Stat_t) fs.UnstableAttr {
	return fs.UnstableAttr{
		Size:             s.Size,
		Usage:            s.Blocks * 512,
		Perms:            fs.FilePermsFromMode(linux.FileMode(s.Mode)),
		Owner:            owner(mo, s),
		AccessTime:       ktime.FromUnix(s.Atim.Sec, s.Atim.Nsec),
		ModificationTime: ktime.FromUnix(s.Mtim.Sec, s.Mtim.Nsec),
		StatusChangeTime: ktime.FromUnix(s.Ctim.Sec, s.Ctim.Nsec),
		Links:            s.Nlink,
	}
}

type dirInfo struct {
	buf  []byte // buffer for directory I/O.
	nbuf int    // length of buf; return value from ReadDirent.
	bufp int    // location of next record in buf.
}

// isBlockError unwraps os errors and checks if they are caused by EAGAIN or
// EWOULDBLOCK. This is so they can be transformed into syserror.ErrWouldBlock.
func isBlockError(err error) bool {
	if err == syserror.EAGAIN || err == syserror.EWOULDBLOCK {
		return true
	}
	if pe, ok := err.(*os.PathError); ok {
		return isBlockError(pe.Err)
	}
	return false
}

func hostEffectiveKIDs() (uint32, []uint32, error) {
	gids, err := os.Getgroups()
	if err != nil {
		return 0, nil, err
	}
	egids := make([]uint32, len(gids))
	for i, gid := range gids {
		egids[i] = uint32(gid)
	}
	return uint32(os.Geteuid()), append(egids, uint32(os.Getegid())), nil
}

var hostUID uint32
var hostGIDs []uint32

func init() {
	hostUID, hostGIDs, _ = hostEffectiveKIDs()
}
