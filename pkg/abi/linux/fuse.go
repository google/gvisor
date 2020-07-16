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

// +marshal
type FUSEOpcode uint32

// +marshal
type FUSEOpID uint64

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
