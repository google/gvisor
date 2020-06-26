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
