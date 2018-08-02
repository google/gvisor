// Copyright 2018 Google Inc.
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

package fs

import (
	"fmt"
	"os"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	ktime "gvisor.googlesource.com/gvisor/pkg/sentry/kernel/time"
)

// InodeType enumerates types of Inodes.
type InodeType int

const (
	// RegularFile is a regular file.
	RegularFile InodeType = iota

	// SpecialFile is a file that doesn't support SeekEnd. It is used for
	// things like proc files.
	SpecialFile

	// Directory is a directory.
	Directory

	// SpecialDirectory is a directory that *does* support SeekEnd. It's
	// the opposite of the SpecialFile scenario above. It similarly
	// supports proc files.
	SpecialDirectory

	// Symlink is a symbolic link.
	Symlink

	// Pipe is a pipe (named or regular).
	Pipe

	// Socket is a socket.
	Socket

	// CharacterDevice is a character device.
	CharacterDevice

	// BlockDevice is a block device.
	BlockDevice

	// Anonymous is an anonymous type when none of the above apply.
	// Epoll fds and event-driven fds fit this category.
	Anonymous
)

// String returns a human-readable representation of the InodeType.
func (n InodeType) String() string {
	switch n {
	case RegularFile, SpecialFile:
		return "file"
	case Directory, SpecialDirectory:
		return "directory"
	case Symlink:
		return "symlink"
	case Pipe:
		return "pipe"
	case Socket:
		return "socket"
	case CharacterDevice:
		return "character-device"
	case BlockDevice:
		return "block-device"
	case Anonymous:
		return "anonymous"
	default:
		return "unknown"
	}
}

// StableAttr contains Inode attributes that will be stable throughout the
// lifetime of the Inode.
type StableAttr struct {
	// Type is the InodeType of a InodeOperations.
	Type InodeType

	// DeviceID is the device on which a InodeOperations resides.
	DeviceID uint64

	// InodeID uniquely identifies InodeOperations on its device.
	InodeID uint64

	// BlockSize is the block size of data backing this InodeOperations.
	BlockSize int64

	// DeviceFileMajor is the major device number of this Node, if it is a
	// device file.
	DeviceFileMajor uint16

	// DeviceFileMinor is the minor device number of this Node, if it is a
	// device file.
	DeviceFileMinor uint32
}

// IsRegular returns true if StableAttr.Type matches a regular file.
func IsRegular(s StableAttr) bool {
	return s.Type == RegularFile
}

// IsFile returns true if StableAttr.Type matches any type of file.
func IsFile(s StableAttr) bool {
	return s.Type == RegularFile || s.Type == SpecialFile
}

// IsDir returns true if StableAttr.Type matches any type of directory.
func IsDir(s StableAttr) bool {
	return s.Type == Directory || s.Type == SpecialDirectory
}

// IsSymlink returns true if StableAttr.Type matches a symlink.
func IsSymlink(s StableAttr) bool {
	return s.Type == Symlink
}

// IsPipe returns true if StableAttr.Type matches any type of pipe.
func IsPipe(s StableAttr) bool {
	return s.Type == Pipe
}

// IsSocket returns true if StableAttr.Type matches any type of socket.
func IsSocket(s StableAttr) bool {
	return s.Type == Socket
}

// IsCharDevice returns true if StableAttr.Type matches a character device.
func IsCharDevice(s StableAttr) bool {
	return s.Type == CharacterDevice
}

// UnstableAttr contains Inode attributes that may change over the lifetime
// of the Inode.
type UnstableAttr struct {
	// Size is the file size in bytes.
	Size int64

	// Usage is the actual data usage in bytes.
	Usage int64

	// Perms is the protection (read/write/execute for user/group/other).
	Perms FilePermissions

	// Owner describes the ownership of this file.
	Owner FileOwner

	// AccessTime is the time of last access
	AccessTime ktime.Time

	// ModificationTime is the time of last modification.
	ModificationTime ktime.Time

	// StatusChangeTime is the time of last attribute modification.
	StatusChangeTime ktime.Time

	// Links is the number of hard links.
	Links uint64
}

// WithCurrentTime returns u with AccessTime == ModificationTime == current time.
func WithCurrentTime(ctx context.Context, u UnstableAttr) UnstableAttr {
	t := ktime.NowFromContext(ctx)
	u.AccessTime = t
	u.ModificationTime = t
	u.StatusChangeTime = t
	return u
}

// AttrMask contains fields to mask StableAttr and UnstableAttr.
type AttrMask struct {
	Type             bool
	DeviceID         bool
	InodeID          bool
	BlockSize        bool
	Size             bool
	Usage            bool
	Perms            bool
	UID              bool
	GID              bool
	AccessTime       bool
	ModificationTime bool
	StatusChangeTime bool
	Links            bool
}

// Empty returns true if all fields in AttrMask are false.
func (a AttrMask) Empty() bool {
	return a == AttrMask{}
}

// Union returns an AttrMask containing the inclusive disjunction of fields in a and b.
func (a AttrMask) Union(b AttrMask) AttrMask {
	return AttrMask{
		Type:             a.Type || b.Type,
		DeviceID:         a.DeviceID || b.DeviceID,
		InodeID:          a.InodeID || b.InodeID,
		BlockSize:        a.BlockSize || b.BlockSize,
		Size:             a.Size || b.Size,
		Usage:            a.Usage || b.Usage,
		Perms:            a.Perms || b.Perms,
		UID:              a.UID || b.UID,
		GID:              a.GID || b.GID,
		AccessTime:       a.AccessTime || b.AccessTime,
		ModificationTime: a.ModificationTime || b.ModificationTime,
		StatusChangeTime: a.StatusChangeTime || b.StatusChangeTime,
		Links:            a.Links || b.Links,
	}
}

// PermMask are file access permissions.
type PermMask struct {
	// Read indicates reading is permitted.
	Read bool

	// Write indicates writing is permitted.
	Write bool

	// Execute indicates execution is permitted.
	Execute bool
}

// OnlyRead returns true when only the read bit is set.
func (p PermMask) OnlyRead() bool {
	return p.Read && !p.Write && !p.Execute
}

// String implements the fmt.Stringer interface for PermMask.
func (p PermMask) String() string {
	return fmt.Sprintf("PermMask{Read: %v, Write: %v, Execute: %v}", p.Read, p.Write, p.Execute)
}

// Mode returns the system mode (syscall.S_IXOTH, etc.) for these permissions
// in the "other" bits.
func (p PermMask) Mode() (mode os.FileMode) {
	if p.Read {
		mode |= syscall.S_IROTH
	}
	if p.Write {
		mode |= syscall.S_IWOTH
	}
	if p.Execute {
		mode |= syscall.S_IXOTH
	}
	return
}

// SupersetOf returns true iff the permissions in p are a superset of the
// permissions in other.
func (p PermMask) SupersetOf(other PermMask) bool {
	if !p.Read && other.Read {
		return false
	}
	if !p.Write && other.Write {
		return false
	}
	if !p.Execute && other.Execute {
		return false
	}
	return true
}

// FilePermissions represents the permissions of a file, with
// Read/Write/Execute bits for user, group, and other.
type FilePermissions struct {
	User  PermMask
	Group PermMask
	Other PermMask

	// Sticky, if set on directories, restricts renaming and deletion of
	// files in those directories to the directory owner, file owner, or
	// CAP_FOWNER. The sticky bit is ignored when set on other files.
	Sticky bool

	// SetUID executables can call UID-setting syscalls without CAP_SETUID.
	SetUID bool

	// SetGID executables can call GID-setting syscalls without CAP_SETGID.
	SetGID bool
}

// PermsFromMode takes the Other permissions (last 3 bits) of a FileMode and
// returns a set of PermMask.
func PermsFromMode(mode linux.FileMode) (perms PermMask) {
	perms.Read = mode&linux.ModeOtherRead != 0
	perms.Write = mode&linux.ModeOtherWrite != 0
	perms.Execute = mode&linux.ModeOtherExec != 0
	return
}

// FilePermsFromP9 converts a p9.FileMode to a FilePermissions struct.
func FilePermsFromP9(mode p9.FileMode) FilePermissions {
	return FilePermsFromMode(linux.FileMode(mode))
}

// FilePermsFromMode converts a system file mode to a FilePermissions struct.
func FilePermsFromMode(mode linux.FileMode) (fp FilePermissions) {
	perm := mode.Permissions()
	fp.Other = PermsFromMode(perm)
	fp.Group = PermsFromMode(perm >> 3)
	fp.User = PermsFromMode(perm >> 6)
	fp.Sticky = mode&linux.ModeSticky == linux.ModeSticky
	fp.SetUID = mode&linux.ModeSetUID == linux.ModeSetUID
	fp.SetGID = mode&linux.ModeSetGID == linux.ModeSetGID
	return
}

// LinuxMode returns the linux mode_t representation of these permissions.
func (f FilePermissions) LinuxMode() linux.FileMode {
	m := linux.FileMode(f.User.Mode()<<6 | f.Group.Mode()<<3 | f.Other.Mode())
	if f.SetUID {
		m |= linux.ModeSetUID
	}
	if f.SetGID {
		m |= linux.ModeSetGID
	}
	if f.Sticky {
		m |= linux.ModeSticky
	}
	return m
}

// OSMode returns the Go runtime's OS independent os.FileMode representation of
// these permissions.
func (f FilePermissions) OSMode() os.FileMode {
	m := os.FileMode(f.User.Mode()<<6 | f.Group.Mode()<<3 | f.Other.Mode())
	if f.SetUID {
		m |= os.ModeSetuid
	}
	if f.SetGID {
		m |= os.ModeSetgid
	}
	if f.Sticky {
		m |= os.ModeSticky
	}
	return m
}

// AnyExecute returns true if any of U/G/O have the execute bit set.
func (f FilePermissions) AnyExecute() bool {
	return f.User.Execute || f.Group.Execute || f.Other.Execute
}

// AnyWrite returns true if any of U/G/O have the write bit set.
func (f FilePermissions) AnyWrite() bool {
	return f.User.Write || f.Group.Write || f.Other.Write
}

// AnyRead returns true if any of U/G/O have the read bit set.
func (f FilePermissions) AnyRead() bool {
	return f.User.Read || f.Group.Read || f.Other.Read
}

// FileOwner represents ownership of a file.
type FileOwner struct {
	UID auth.KUID
	GID auth.KGID
}

// RootOwner corresponds to KUID/KGID 0/0.
var RootOwner = FileOwner{
	UID: auth.RootKUID,
	GID: auth.RootKGID,
}
