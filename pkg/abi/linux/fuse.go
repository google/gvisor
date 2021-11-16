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

package linux

import (
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// FUSEOpcode is a FUSE operation code.
//
// +marshal
type FUSEOpcode uint32

// FUSEOpID is a FUSE operation ID.
//
// +marshal
type FUSEOpID uint64

// FUSE_ROOT_ID is the id of root inode.
const FUSE_ROOT_ID = 1

// Opcodes for FUSE operations.
//
// Analogous to the opcodes in include/linux/fuse.h.
const (
	FUSE_LOOKUP   FUSEOpcode = 1
	FUSE_FORGET              = 2 /* no reply */
	FUSE_GETATTR             = 3
	FUSE_SETATTR             = 4
	FUSE_READLINK            = 5
	FUSE_SYMLINK             = 6
	_
	FUSE_MKNOD   = 8
	FUSE_MKDIR   = 9
	FUSE_UNLINK  = 10
	FUSE_RMDIR   = 11
	FUSE_RENAME  = 12
	FUSE_LINK    = 13
	FUSE_OPEN    = 14
	FUSE_READ    = 15
	FUSE_WRITE   = 16
	FUSE_STATFS  = 17
	FUSE_RELEASE = 18
	_
	FUSE_FSYNC        = 20
	FUSE_SETXATTR     = 21
	FUSE_GETXATTR     = 22
	FUSE_LISTXATTR    = 23
	FUSE_REMOVEXATTR  = 24
	FUSE_FLUSH        = 25
	FUSE_INIT         = 26
	FUSE_OPENDIR      = 27
	FUSE_READDIR      = 28
	FUSE_RELEASEDIR   = 29
	FUSE_FSYNCDIR     = 30
	FUSE_GETLK        = 31
	FUSE_SETLK        = 32
	FUSE_SETLKW       = 33
	FUSE_ACCESS       = 34
	FUSE_CREATE       = 35
	FUSE_INTERRUPT    = 36
	FUSE_BMAP         = 37
	FUSE_DESTROY      = 38
	FUSE_IOCTL        = 39
	FUSE_POLL         = 40
	FUSE_NOTIFY_REPLY = 41
	FUSE_BATCH_FORGET = 42
)

const (
	// FUSE_MIN_READ_BUFFER is the minimum size the read can be for any FUSE filesystem.
	// This is the minimum size Linux supports. See linux.fuse.h.
	FUSE_MIN_READ_BUFFER uint32 = 8192
)

// FUSEHeaderIn is the header read by the daemon with each request.
//
// +marshal
type FUSEHeaderIn struct {
	// Len specifies the total length of the data, including this header.
	Len uint32

	// Opcode specifies the kind of operation of the request.
	Opcode FUSEOpcode

	// Unique specifies the unique identifier for this request.
	Unique FUSEOpID

	// NodeID is the ID of the filesystem object being operated on.
	NodeID uint64

	// UID is the UID of the requesting process.
	UID uint32

	// GID is the GID of the requesting process.
	GID uint32

	// PID is the PID of the requesting process.
	PID uint32

	_ uint32
}

// FUSEHeaderOut is the header written by the daemon when it processes
// a request and wants to send a reply (almost all operations require a
// reply; if they do not, this will be explicitly documented).
//
// +marshal
type FUSEHeaderOut struct {
	// Len specifies the total length of the data, including this header.
	Len uint32

	// Error specifies the error that occurred (0 if none).
	Error int32

	// Unique specifies the unique identifier of the corresponding request.
	Unique FUSEOpID
}

// FUSE_INIT flags, consistent with the ones in include/uapi/linux/fuse.h.
// Our taget version is 7.23 but we have few implemented in advance.
const (
	FUSE_ASYNC_READ       = 1 << 0
	FUSE_POSIX_LOCKS      = 1 << 1
	FUSE_FILE_OPS         = 1 << 2
	FUSE_ATOMIC_O_TRUNC   = 1 << 3
	FUSE_EXPORT_SUPPORT   = 1 << 4
	FUSE_BIG_WRITES       = 1 << 5
	FUSE_DONT_MASK        = 1 << 6
	FUSE_SPLICE_WRITE     = 1 << 7
	FUSE_SPLICE_MOVE      = 1 << 8
	FUSE_SPLICE_READ      = 1 << 9
	FUSE_FLOCK_LOCKS      = 1 << 10
	FUSE_HAS_IOCTL_DIR    = 1 << 11
	FUSE_AUTO_INVAL_DATA  = 1 << 12
	FUSE_DO_READDIRPLUS   = 1 << 13
	FUSE_READDIRPLUS_AUTO = 1 << 14
	FUSE_ASYNC_DIO        = 1 << 15
	FUSE_WRITEBACK_CACHE  = 1 << 16
	FUSE_NO_OPEN_SUPPORT  = 1 << 17
	FUSE_MAX_PAGES        = 1 << 22 // From FUSE 7.28
)

// currently supported FUSE protocol version numbers.
const (
	FUSE_KERNEL_VERSION       = 7
	FUSE_KERNEL_MINOR_VERSION = 31
)

// Constants relevant to FUSE operations.
const (
	FUSE_NAME_MAX     = 1024
	FUSE_PAGE_SIZE    = 4096
	FUSE_DIRENT_ALIGN = 8
)

// FUSEInitIn is the request sent by the kernel to the daemon,
// to negotiate the version and flags.
//
// +marshal
type FUSEInitIn struct {
	// Major version supported by kernel.
	Major uint32

	// Minor version supported by the kernel.
	Minor uint32

	// MaxReadahead is the maximum number of bytes to read-ahead
	// decided by the kernel.
	MaxReadahead uint32

	// Flags of this init request.
	Flags uint32
}

// FUSEInitOut is the reply sent by the daemon to the kernel
// for FUSEInitIn. We target FUSE 7.23; this struct supports 7.28.
//
// +marshal
type FUSEInitOut struct {
	// Major version supported by daemon.
	Major uint32

	// Minor version supported by daemon.
	Minor uint32

	// MaxReadahead is the maximum number of bytes to read-ahead.
	// Decided by the daemon, after receiving the value from kernel.
	MaxReadahead uint32

	// Flags of this init reply.
	Flags uint32

	// MaxBackground is the maximum number of pending background requests
	// that the daemon wants.
	MaxBackground uint16

	// CongestionThreshold is the daemon-decided threshold for
	// the number of the pending background requests.
	CongestionThreshold uint16

	// MaxWrite is the daemon's maximum size of a write buffer.
	// Kernel adjusts it to the minimum (fuse/init.go:fuseMinMaxWrite).
	// if the value from daemon is too small.
	MaxWrite uint32

	// TimeGran is the daemon's time granularity for mtime and ctime metadata.
	// The unit is nanosecond.
	// Value should be power of 10.
	// 1 indicates full nanosecond granularity support.
	TimeGran uint32

	// MaxPages is the daemon's maximum number of pages for one write operation.
	// Kernel adjusts it to the maximum (fuse/init.go:FUSE_MAX_MAX_PAGES).
	// if the value from daemon is too large.
	MaxPages uint16

	_ uint16

	_ [8]uint32
}

// FUSE_GETATTR_FH is currently the only flag of FUSEGetAttrIn.GetAttrFlags.
// If it is set, the file handle (FUSEGetAttrIn.Fh) is used to indicate the
// object instead of the node id attribute in the request header.
const FUSE_GETATTR_FH = (1 << 0)

// FUSEGetAttrIn is the request sent by the kernel to the daemon,
// to get the attribute of a inode.
//
// +marshal
type FUSEGetAttrIn struct {
	// GetAttrFlags specifies whether getattr request is sent with a nodeid or
	// with a file handle.
	GetAttrFlags uint32

	_ uint32

	// Fh is the file handler when GetAttrFlags has FUSE_GETATTR_FH bit. If
	// used, the operation is analogous to fstat(2).
	Fh uint64
}

// FUSEAttr is the struct used in the reponse FUSEGetAttrOut.
//
// +marshal
type FUSEAttr struct {
	// Ino is the inode number of this file.
	Ino uint64

	// Size is the size of this file.
	Size uint64

	// Blocks is the number of the 512B blocks allocated by this file.
	Blocks uint64

	// Atime is the time of last access.
	Atime uint64

	// Mtime is the time of last modification.
	Mtime uint64

	// Ctime is the time of last status change.
	Ctime uint64

	// AtimeNsec is the nano second part of Atime.
	AtimeNsec uint32

	// MtimeNsec is the nano second part of Mtime.
	MtimeNsec uint32

	// CtimeNsec is the nano second part of Ctime.
	CtimeNsec uint32

	// Mode contains the file type and mode.
	Mode uint32

	// Nlink is the number of the hard links.
	Nlink uint32

	// UID is user ID of the owner.
	UID uint32

	// GID is group ID of the owner.
	GID uint32

	// Rdev is the device ID if this is a special file.
	Rdev uint32

	// BlkSize is the block size for filesystem I/O.
	BlkSize uint32

	_ uint32
}

// FUSEGetAttrOut is the reply sent by the daemon to the kernel
// for FUSEGetAttrIn.
//
// +marshal
type FUSEGetAttrOut struct {
	// AttrValid and AttrValidNsec describe the attribute cache duration
	AttrValid uint64

	// AttrValidNsec is the nanosecond part of the attribute cache duration
	AttrValidNsec uint32

	_ uint32

	// Attr contains the metadata returned from the FUSE server
	Attr FUSEAttr
}

// FUSEEntryOut is the reply sent by the daemon to the kernel
// for FUSE_MKNOD, FUSE_MKDIR, FUSE_SYMLINK, FUSE_LINK and
// FUSE_LOOKUP.
//
// +marshal
type FUSEEntryOut struct {
	// NodeID is the ID for current inode.
	NodeID uint64

	// Generation is the generation number of inode.
	// Used to identify an inode that have different ID at different time.
	Generation uint64

	// EntryValid indicates timeout for an entry.
	EntryValid uint64

	// AttrValid indicates timeout for an entry's attributes.
	AttrValid uint64

	// EntryValidNsec indicates timeout for an entry in nanosecond.
	EntryValidNSec uint32

	// AttrValidNsec indicates timeout for an entry's attributes in nanosecond.
	AttrValidNSec uint32

	// Attr contains the attributes of an entry.
	Attr FUSEAttr
}

// CString represents a null terminated string which can be marshalled.
//
// +marshal dynamic
type CString string

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *CString) MarshalBytes(buf []byte) []byte {
	copy(buf, *s)
	buf[len(*s)] = 0 // null char
	return buf[s.SizeBytes():]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *CString) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, CString is never unmarshalled")
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *CString) SizeBytes() int {
	// 1 extra byte for null-terminated string.
	return len(*s) + 1
}

// FUSELookupIn is the request sent by the kernel to the daemon
// to look up a file name.
//
// +marshal dynamic
type FUSELookupIn struct {
	// Name is a file name to be looked up.
	Name CString
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *FUSELookupIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSELookupIn is never unmarshalled")
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *FUSELookupIn) MarshalBytes(buf []byte) []byte {
	return r.Name.MarshalBytes(buf)
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *FUSELookupIn) SizeBytes() int {
	return r.Name.SizeBytes()
}

// MAX_NON_LFS indicates the maximum offset without large file support.
const MAX_NON_LFS = ((1 << 31) - 1)

// flags returned by OPEN request.
const (
	// FOPEN_DIRECT_IO indicates bypassing page cache for this opened file.
	FOPEN_DIRECT_IO = 1 << 0
	// FOPEN_KEEP_CACHE avoids invalidate of data cache on open.
	FOPEN_KEEP_CACHE = 1 << 1
	// FOPEN_NONSEEKABLE indicates the file cannot be seeked.
	FOPEN_NONSEEKABLE = 1 << 2
)

// FUSEOpenIn is the request sent by the kernel to the daemon,
// to negotiate flags and get file handle.
//
// +marshal
type FUSEOpenIn struct {
	// Flags of this open request.
	Flags uint32

	_ uint32
}

// FUSEOpenOut is the reply sent by the daemon to the kernel
// for FUSEOpenIn.
//
// +marshal
type FUSEOpenOut struct {
	// Fh is the file handler for opened file.
	Fh uint64

	// OpenFlag for the opened file.
	OpenFlag uint32

	_ uint32
}

// FUSE_READ flags, consistent with the ones in include/uapi/linux/fuse.h.
const (
	FUSE_READ_LOCKOWNER = 1 << 1
)

// FUSEReadIn is the request sent by the kernel to the daemon
// for FUSE_READ.
//
// +marshal
type FUSEReadIn struct {
	// Fh is the file handle in userspace.
	Fh uint64

	// Offset is the read offset.
	Offset uint64

	// Size is the number of bytes to read.
	Size uint32

	// ReadFlags for this FUSE_READ request.
	// Currently only contains FUSE_READ_LOCKOWNER.
	ReadFlags uint32

	// LockOwner is the id of the lock owner if there is one.
	LockOwner uint64

	// Flags for the underlying file.
	Flags uint32

	_ uint32
}

// FUSEWriteIn is the first part of the payload of the
// request sent by the kernel to the daemon
// for FUSE_WRITE (struct for FUSE version >= 7.9).
//
// The second part of the payload is the
// binary bytes of the data to be written.
//
// +marshal
type FUSEWriteIn struct {
	// Fh is the file handle in userspace.
	Fh uint64

	// Offset is the write offset.
	Offset uint64

	// Size is the number of bytes to write.
	Size uint32

	// ReadFlags for this FUSE_WRITE request.
	WriteFlags uint32

	// LockOwner is the id of the lock owner if there is one.
	LockOwner uint64

	// Flags for the underlying file.
	Flags uint32

	_ uint32
}

// FUSEWriteOut is the payload of the reply sent by the daemon to the kernel
// for a FUSE_WRITE request.
//
// +marshal
type FUSEWriteOut struct {
	// Size is the number of bytes written.
	Size uint32

	_ uint32
}

// FUSEReleaseIn is the request sent by the kernel to the daemon
// when there is no more reference to a file.
//
// +marshal
type FUSEReleaseIn struct {
	// Fh is the file handler for the file to be released.
	Fh uint64

	// Flags of the file.
	Flags uint32

	// ReleaseFlags of this release request.
	ReleaseFlags uint32

	// LockOwner is the id of the lock owner if there is one.
	LockOwner uint64
}

// FUSECreateMeta contains all the static fields of FUSECreateIn,
// which is used for FUSE_CREATE.
//
// +marshal
type FUSECreateMeta struct {
	// Flags of the creating file.
	Flags uint32

	// Mode is the mode of the creating file.
	Mode uint32

	// Umask is the current file mode creation mask.
	Umask uint32
	_     uint32
}

// FUSECreateIn contains all the arguments sent by the kernel to the daemon, to
// atomically create and open a new regular file.
//
// +marshal dynamic
type FUSECreateIn struct {
	// CreateMeta contains mode, rdev and umash field for FUSE_MKNODS.
	CreateMeta FUSECreateMeta

	// Name is the name of the node to create.
	Name CString
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *FUSECreateIn) MarshalBytes(buf []byte) []byte {
	buf = r.CreateMeta.MarshalBytes(buf)
	return r.Name.MarshalBytes(buf)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *FUSECreateIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSECreateIn is never unmarshalled")
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *FUSECreateIn) SizeBytes() int {
	return r.CreateMeta.SizeBytes() + r.Name.SizeBytes()
}

// FUSEMknodMeta contains all the static fields of FUSEMknodIn,
// which is used for FUSE_MKNOD.
//
// +marshal
type FUSEMknodMeta struct {
	// Mode of the inode to create.
	Mode uint32

	// Rdev encodes device major and minor information.
	Rdev uint32

	// Umask is the current file mode creation mask.
	Umask uint32

	_ uint32
}

// FUSEMknodIn contains all the arguments sent by the kernel
// to the daemon, to create a new file node.
//
// +marshal dynamic
type FUSEMknodIn struct {
	// MknodMeta contains mode, rdev and umash field for FUSE_MKNODS.
	MknodMeta FUSEMknodMeta
	// Name is the name of the node to create.
	Name CString
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *FUSEMknodIn) MarshalBytes(buf []byte) []byte {
	buf = r.MknodMeta.MarshalBytes(buf)
	return r.Name.MarshalBytes(buf)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *FUSEMknodIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEMknodIn is never unmarshalled")
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *FUSEMknodIn) SizeBytes() int {
	return r.MknodMeta.SizeBytes() + r.Name.SizeBytes()
}

// FUSESymlinkIn is the request sent by the kernel to the daemon,
// to create a symbolic link.
//
// +marshal dynamic
type FUSESymlinkIn struct {
	// Name of symlink to create.
	Name CString

	// Target of the symlink.
	Target CString
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *FUSESymlinkIn) MarshalBytes(buf []byte) []byte {
	buf = r.Name.MarshalBytes(buf)
	return r.Target.MarshalBytes(buf)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *FUSESymlinkIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEMknodIn is never unmarshalled")
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *FUSESymlinkIn) SizeBytes() int {
	return r.Name.SizeBytes() + r.Target.SizeBytes()
}

// FUSEEmptyIn is used by operations without request body.
//
// +marshal dynamic
type FUSEEmptyIn struct{}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *FUSEEmptyIn) MarshalBytes(buf []byte) []byte {
	return buf
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *FUSEEmptyIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEEmptyIn is never unmarshalled")
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *FUSEEmptyIn) SizeBytes() int {
	return 0
}

// FUSEMkdirMeta contains all the static fields of FUSEMkdirIn,
// which is used for FUSE_MKDIR.
//
// +marshal
type FUSEMkdirMeta struct {
	// Mode of the directory of create.
	Mode uint32
	// Umask is the user file creation mask.
	Umask uint32
}

// FUSEMkdirIn contains all the arguments sent by the kernel
// to the daemon, to create a new directory.
//
// +marshal dynamic
type FUSEMkdirIn struct {
	// MkdirMeta contains Mode and Umask of the directory to create.
	MkdirMeta FUSEMkdirMeta
	// Name of the directory to create.
	Name CString
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *FUSEMkdirIn) MarshalBytes(buf []byte) []byte {
	buf = r.MkdirMeta.MarshalBytes(buf)
	return r.Name.MarshalBytes(buf)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *FUSEMkdirIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEMkdirIn is never unmarshalled")
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *FUSEMkdirIn) SizeBytes() int {
	return r.MkdirMeta.SizeBytes() + r.Name.SizeBytes()
}

// FUSERmDirIn is the request sent by the kernel to the daemon
// when trying to remove a directory.
//
// +marshal dynamic
type FUSERmDirIn struct {
	// Name is a directory name to be removed.
	Name CString
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *FUSERmDirIn) MarshalBytes(buf []byte) []byte {
	return r.Name.MarshalBytes(buf)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *FUSERmDirIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSERmDirIn is never unmarshalled")
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *FUSERmDirIn) SizeBytes() int {
	return r.Name.SizeBytes()
}

// FUSEDirents is a list of Dirents received from the FUSE daemon server.
// It is used for FUSE_READDIR.
//
// +marshal dynamic
type FUSEDirents struct {
	Dirents []*FUSEDirent
}

// FUSEDirent is a Dirent received from the FUSE daemon server.
// It is used for FUSE_READDIR.
//
// +marshal dynamic
type FUSEDirent struct {
	// Meta contains all the static fields of FUSEDirent.
	Meta FUSEDirentMeta
	// Name is the filename of the dirent.
	Name string
}

// FUSEDirentMeta contains all the static fields of FUSEDirent.
// It is used for FUSE_READDIR.
//
// +marshal
type FUSEDirentMeta struct {
	// Inode of the dirent.
	Ino uint64
	// Offset of the dirent.
	Off uint64
	// NameLen is the length of the dirent name.
	NameLen uint32
	// Type of the dirent.
	Type uint32
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *FUSEDirents) SizeBytes() int {
	var sizeBytes int
	for _, dirent := range r.Dirents {
		sizeBytes += dirent.SizeBytes()
	}

	return sizeBytes
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *FUSEDirents) MarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEDirents is never marshalled")
}

// UnmarshalBytes deserializes FUSEDirents from the src buffer.
func (r *FUSEDirents) UnmarshalBytes(src []byte) []byte {
	for {
		if len(src) <= (*FUSEDirentMeta)(nil).SizeBytes() {
			break
		}

		// Its unclear how many dirents there are in src. Each dirent is dynamically
		// sized and so we can't make assumptions about how many dirents we can allocate.
		if r.Dirents == nil {
			r.Dirents = make([]*FUSEDirent, 0)
		}

		// We have to allocate a struct for each dirent - there must be a better way
		// to do this. Linux allocates 1 page to store all the dirents and then
		// simply reads them from the page.
		var dirent FUSEDirent
		src = dirent.UnmarshalBytes(src)
		r.Dirents = append(r.Dirents, &dirent)
	}
	return src
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *FUSEDirent) SizeBytes() int {
	dataSize := r.Meta.SizeBytes() + len(r.Name)

	// Each Dirent must be padded such that its size is a multiple
	// of FUSE_DIRENT_ALIGN. Similar to the fuse dirent alignment
	// in linux/fuse.h.
	return (dataSize + (FUSE_DIRENT_ALIGN - 1)) & ^(FUSE_DIRENT_ALIGN - 1)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *FUSEDirent) MarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEDirent is never marshalled")
}

// shiftNextDirent advances buf to the start of the next dirent, per
// FUSE ABI. buf should begin at the start of a dirent.
func (r *FUSEDirent) shiftNextDirent(buf []byte) []byte {
	nextOff := r.SizeBytes()
	if nextOff > len(buf) { // Handle overflow.
		return buf[len(buf):]
	}
	return buf[nextOff:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *FUSEDirent) UnmarshalBytes(src []byte) []byte {
	srcP := r.Meta.UnmarshalBytes(src)

	if r.Meta.NameLen > FUSE_NAME_MAX {
		// The name is too long and therefore invalid. We don't
		// need to unmarshal the name since it'll be thrown away.
		return r.shiftNextDirent(src)
	}

	buf := make([]byte, r.Meta.NameLen)
	name := primitive.ByteSlice(buf)
	name.UnmarshalBytes(srcP[:r.Meta.NameLen])
	r.Name = string(name)
	return r.shiftNextDirent(src)
}

// FATTR_* consts are the attribute flags defined in include/uapi/linux/fuse.h.
// These should be or-ed together for setattr to know what has been changed.
const (
	FATTR_MODE      = (1 << 0)
	FATTR_UID       = (1 << 1)
	FATTR_GID       = (1 << 2)
	FATTR_SIZE      = (1 << 3)
	FATTR_ATIME     = (1 << 4)
	FATTR_MTIME     = (1 << 5)
	FATTR_FH        = (1 << 6)
	FATTR_ATIME_NOW = (1 << 7)
	FATTR_MTIME_NOW = (1 << 8)
	FATTR_LOCKOWNER = (1 << 9)
	FATTR_CTIME     = (1 << 10)
)

// FUSESetAttrIn is the request sent by the kernel to the daemon,
// to set the attribute(s) of a file.
//
// +marshal
type FUSESetAttrIn struct {
	// Valid indicates which attributes are modified by this request.
	Valid uint32

	_ uint32

	// Fh is used to identify the file if FATTR_FH is set in Valid.
	Fh uint64

	// Size is the size that the request wants to change to.
	Size uint64

	// LockOwner is the owner of the lock that the request wants to change to.
	LockOwner uint64

	// Atime is the access time that the request wants to change to.
	Atime uint64

	// Mtime is the modification time that the request wants to change to.
	Mtime uint64

	// Ctime is the status change time that the request wants to change to.
	Ctime uint64

	// AtimeNsec is the nano second part of Atime.
	AtimeNsec uint32

	// MtimeNsec is the nano second part of Mtime.
	MtimeNsec uint32

	// CtimeNsec is the nano second part of Ctime.
	CtimeNsec uint32

	// Mode is the file mode that the request wants to change to.
	Mode uint32

	_ uint32

	// UID is the user ID of the owner that the request wants to change to.
	UID uint32

	// GID is the group ID of the owner that the request wants to change to.
	GID uint32

	_ uint32
}

// FUSEUnlinkIn is the request sent by the kernel to the daemon
// when trying to unlink a node.
//
// +marshal dynamic
type FUSEUnlinkIn struct {
	// Name of the node to unlink.
	Name CString
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (r *FUSEUnlinkIn) MarshalBytes(buf []byte) []byte {
	return r.Name.MarshalBytes(buf)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (r *FUSEUnlinkIn) UnmarshalBytes(buf []byte) []byte {
	panic("Unimplemented, FUSEUnlinkIn is never unmarshalled")
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (r *FUSEUnlinkIn) SizeBytes() int {
	return r.Name.SizeBytes()
}
