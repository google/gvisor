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

import "gvisor.dev/gvisor/tools/go_marshal/marshal"

// +marshal
type FUSEOpcode uint32

// +marshal
type FUSEOpID uint64

// FUSE_ROOT_ID is the id of root inode.
const FUSE_ROOT_ID = 1

// Opcodes for FUSE operations. Analogous to the opcodes in include/linux/fuse.h.
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

// FUSEWriteIn is the header written by a daemon when it makes a
// write request to the FUSE filesystem.
//
// +marshal
type FUSEWriteIn struct {
	// Fh specifies the file handle that is being written to.
	Fh uint64

	// Offset is the offset of the write.
	Offset uint64

	// Size is the size of data being written.
	Size uint32

	// WriteFlags is the flags used during the write.
	WriteFlags uint32

	// LockOwner is the ID of the lock owner.
	LockOwner uint64

	// Flags is the flags for the request.
	Flags uint32

	_ uint32
}

// FUSE_INIT flags, consistent with the ones in include/uapi/linux/fuse.h.
const (
	FUSE_ASYNC_READ          = 1 << 0
	FUSE_POSIX_LOCKS         = 1 << 1
	FUSE_FILE_OPS            = 1 << 2
	FUSE_ATOMIC_O_TRUNC      = 1 << 3
	FUSE_EXPORT_SUPPORT      = 1 << 4
	FUSE_BIG_WRITES          = 1 << 5
	FUSE_DONT_MASK           = 1 << 6
	FUSE_SPLICE_WRITE        = 1 << 7
	FUSE_SPLICE_MOVE         = 1 << 8
	FUSE_SPLICE_READ         = 1 << 9
	FUSE_FLOCK_LOCKS         = 1 << 10
	FUSE_HAS_IOCTL_DIR       = 1 << 11
	FUSE_AUTO_INVAL_DATA     = 1 << 12
	FUSE_DO_READDIRPLUS      = 1 << 13
	FUSE_READDIRPLUS_AUTO    = 1 << 14
	FUSE_ASYNC_DIO           = 1 << 15
	FUSE_WRITEBACK_CACHE     = 1 << 16
	FUSE_NO_OPEN_SUPPORT     = 1 << 17
	FUSE_PARALLEL_DIROPS     = 1 << 18
	FUSE_HANDLE_KILLPRIV     = 1 << 19
	FUSE_POSIX_ACL           = 1 << 20
	FUSE_ABORT_ERROR         = 1 << 21
	FUSE_MAX_PAGES           = 1 << 22
	FUSE_CACHE_SYMLINKS      = 1 << 23
	FUSE_NO_OPENDIR_SUPPORT  = 1 << 24
	FUSE_EXPLICIT_INVAL_DATA = 1 << 25
	FUSE_MAP_ALIGNMENT       = 1 << 26
)

// currently supported FUSE protocol version numbers.
const (
	FUSE_KERNEL_VERSION       = 7
	FUSE_KERNEL_MINOR_VERSION = 31
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
// for FUSEInitIn.
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

	// MapAlignment is an unknown field and not used by this package at this moment.
	// Use as a placeholder to be consistent with the FUSE protocol.
	MapAlignment uint16

	_ [8]uint32
}

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
	Ino       uint64
	Size      uint64
	Blocks    uint64
	Atime     uint64
	Mtime     uint64
	Ctime     uint64
	AtimeNsec uint32
	MtimeNsec uint32
	CtimeNsec uint32
	Mode      uint32
	Nlink     uint32
	UID       uint32
	GID       uint32
	Rdev      uint32
	BlkSize   uint32
	_         uint32
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

// FUSELookupIn is the request sent by the kernel to the daemon
// to look up a file name.
//
// Dynamically-sized objects cannot be marshalled.
type FUSELookupIn struct {
	marshal.StubMarshallable

	// Name is a file name to be looked up.
	Name string
}

// MarshalUnsafe serializes r.name to the dst buffer.
func (r *FUSELookupIn) MarshalUnsafe(buf []byte) {
	copy(buf, []byte(r.Name))
}

// SizeBytes is the size of the memory representation of FUSELookupIn.
// 1 extra byte for null-terminated string.
func (r *FUSELookupIn) SizeBytes() int {
	return len(r.Name) + 1
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
// Dynamically-sized objects cannot be marshalled.
type FUSEMknodIn struct {
	marshal.StubMarshallable

	// MknodMeta contains mode, rdev and umash field for FUSE_MKNODS.
	MknodMeta FUSEMknodMeta

	// Name is the name of the node to create.
	Name string
}

// MarshalUnsafe serializes r.MknodMeta and r.Name to the dst buffer.
func (r *FUSEMknodIn) MarshalUnsafe(buf []byte) {
	r.MknodMeta.MarshalUnsafe(buf[:r.MknodMeta.SizeBytes()])
	copy(buf[r.MknodMeta.SizeBytes():], r.Name)
}

// SizeBytes is the size of the memory representation of FUSEMknodIn.
// 1 extra byte for null-terminated string.
func (r *FUSEMknodIn) SizeBytes() int {
	return r.MknodMeta.SizeBytes() + len(r.Name) + 1
}

// FUSESymLinkIn is the request sent by the kernel to the daemon,
// to create a symbolic link.
//
// Dynamically-sized objects cannot be marshalled.
type FUSESymLinkIn struct {
	marshal.StubMarshallable

	// Name of symlink to create.
	Name string

	// Target of the symlink.
	Target string
}

// MarshalUnsafe serializes r.Name and r.Target to the dst buffer.
// Left null-termination at end of r.Name and r.Target.
func (r *FUSESymLinkIn) MarshalUnsafe(buf []byte) {
	copy(buf, r.Name)
	copy(buf[len(r.Name)+1:], r.Target)
}

// SizeBytes is the size of the memory representation of FUSESymLinkIn.
// 2 extra bytes for null-terminated string.
func (r *FUSESymLinkIn) SizeBytes() int {
	return len(r.Name) + len(r.Target) + 2
}

// FUSEEmptyIn is used by operations without request body.
type FUSEEmptyIn struct{ marshal.StubMarshallable }

// MarshalUnsafe do nothing for marshal.
func (r *FUSEEmptyIn) MarshalUnsafe(buf []byte) {}

// SizeBytes is 0 for empty request.
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
// Dynamically-sized objects cannot be marshalled.
type FUSEMkdirIn struct {
	marshal.StubMarshallable

	// MkdirMeta contains Mode and Umask of the directory to create.
	MkdirMeta FUSEMkdirMeta

	// Name of the directory to create.
	Name string
}

// MarshalUnsafe serializes r.MkdirMeta and r.Name to the dst buffer.
func (r *FUSEMkdirIn) MarshalUnsafe(buf []byte) {
	r.MkdirMeta.MarshalUnsafe(buf[:r.MkdirMeta.SizeBytes()])
	copy(buf[r.MkdirMeta.SizeBytes():], r.Name)
}

// SizeBytes is the size of the memory representation of FUSEMkdirIn.
// 1 extra byte for null-terminated Name string.
func (r *FUSEMkdirIn) SizeBytes() int {
	return r.MkdirMeta.SizeBytes() + len(r.Name) + 1
}
