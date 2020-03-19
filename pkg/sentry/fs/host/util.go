// Copyright 2018 The gVisor Authors.
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
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/device"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/syserror"
)

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

func owner(s *syscall.Stat_t) fs.FileOwner {
	return fs.FileOwner{
		UID: auth.KUID(s.Uid),
		GID: auth.KGID(s.Gid),
	}
}

func unstableAttr(s *syscall.Stat_t) fs.UnstableAttr {
	return fs.UnstableAttr{
		Size:             s.Size,
		Usage:            s.Blocks * 512,
		Perms:            fs.FilePermsFromMode(linux.FileMode(s.Mode)),
		Owner:            owner(s),
		AccessTime:       ktime.FromUnix(s.Atim.Sec, s.Atim.Nsec),
		ModificationTime: ktime.FromUnix(s.Mtim.Sec, s.Mtim.Nsec),
		StatusChangeTime: ktime.FromUnix(s.Ctim.Sec, s.Ctim.Nsec),
		Links:            uint64(s.Nlink),
	}
}

type dirInfo struct {
	buf  []byte // buffer for directory I/O.
	nbuf int    // length of buf; return value from ReadDirent.
	bufp int    // location of next record in buf.
}

// LINT.IfChange

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

// LINT.ThenChange(../../fsimpl/host/util.go)

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
