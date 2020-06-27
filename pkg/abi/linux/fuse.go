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

package linux

// +marshal
type FUSEOpcode uint32

// +marshal
type FUSEOpID uint64

// Opcodes for FUSE operations. Analogous to the opcodes in include/linux/fuse.h.
const (
	FUSE_LOOKUP FUSEOpcode = iota + 1
	FUSE_FORGET            /* no reply */
	FUSE_GETATTR
	FUSE_SETATTR
	FUSE_READLINK
	FUSE_SYMLINK
	_
	FUSE_MKNOD
	FUSE_MKDIR
	FUSE_UNLINK
	FUSE_RMDIR
	FUSE_RENAME
	FUSE_LINK
	FUSE_OPEN
	FUSE_READ
	FUSE_WRITE
	FUSE_STATFS
	FUSE_RELEASE
	_
	FUSE_FSYNC
	FUSE_SETXATTR
	FUSE_GETXATTR
	FUSE_LISTXATTR
	FUSE_REMOVEXATTR
	FUSE_FLUSH
	FUSE_INIT
	FUSE_OPENDIR
	FUSE_READDIR
	FUSE_RELEASEDIR
	FUSE_FSYNCDIR
	FUSE_GETLK
	FUSE_SETLK
	FUSE_SETLKW
	FUSE_ACCESS
	FUSE_CREATE
	FUSE_INTERRUPT
	FUSE_BMAP
	FUSE_DESTROY
	FUSE_IOCTL
	FUSE_POLL
	FUSE_NOTIFY_REPLY
	FUSE_BATCH_FORGET
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

	padding uint32
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

// FUSE_INIT flags, from include/uapi/linux/fuse.h.
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

// const version numbers from include/uapi/linux/fuse.h.
const (
	FUSE_KERNEL_VERSION = 7
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

	// MaxReadahead is the maximum number of bytes to read-ahead.
	MaxReadahead uint32

	// Flags of init_in request.
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
	MaxReadahead uint32

	// Flags of init_out reply.
	Flags uint32

	// MaxBackground is the maximum number of pending "background" requests.
	MaxBackground uint16

	// CongestionThreshold parameter used by the kernel.
	// FUSE mark the filesystem as "congested" when the number of pending
	// background requests exceeds this threshold.
	CongestionThreshold uint16

	// MaxWrite the maximum size of a write buffer.
	// Minmum value is FUSE_MIN_MAX_WRITE.
	MaxWrite uint32

	// TimeGran is the time granularity for mtime and ctime supported by the filesystem.
	// Values should be power of 10 and unit is nanosecond.
	// 1 indicates full nanosecond granularity support.
	TimeGran uint32

	// MaxPages the maximum number of pages for one write operation.
	// Maximum value is FUSE_MAX_MAX_PAGES.
	MaxPages uint16

	// MapAlignment is an unknown field and not used at this moment.
	MapAlignment uint16

	unused [8]uint32
}
