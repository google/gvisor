// Copyright 2019 The gVisor Authors.
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
	"encoding/binary"
	"structs"
)

// Constants for extended attributes.
const (
	XATTR_NAME_MAX = 255
	XATTR_SIZE_MAX = 65536
	XATTR_LIST_MAX = 65536

	XATTR_CREATE  = 1
	XATTR_REPLACE = 2

	XATTR_SECURITY_PREFIX     = "security."
	XATTR_SECURITY_PREFIX_LEN = len(XATTR_SECURITY_PREFIX)

	XATTR_SECURITY_CAPABILITY = XATTR_SECURITY_PREFIX + "capability"

	XATTR_SYSTEM_PREFIX     = "system."
	XATTR_SYSTEM_PREFIX_LEN = len(XATTR_SYSTEM_PREFIX)

	XATTR_TRUSTED_PREFIX     = "trusted."
	XATTR_TRUSTED_PREFIX_LEN = len(XATTR_TRUSTED_PREFIX)

	XATTR_USER_PREFIX     = "user."
	XATTR_USER_PREFIX_LEN = len(XATTR_USER_PREFIX)
)

// Constants for POSIX ACL extended attributes.
const (
	// Extended attribute names for POSIX ACLs.
	XATTR_NAME_POSIX_ACL_ACCESS  = XATTR_SYSTEM_PREFIX + "posix_acl_access"
	XATTR_NAME_POSIX_ACL_DEFAULT = XATTR_SYSTEM_PREFIX + "posix_acl_default"

	POSIX_ACL_XATTR_VERSION = 2

	// ACL_UNDEFINED_ID is the ID for entries that do not contain a
	// named user or group.
	ACL_UNDEFINED_ID = 0xffffffff

	// ACL entry tags.
	ACL_USER_OBJ  = 0x01
	ACL_USER      = 0x02
	ACL_GROUP_OBJ = 0x04
	ACL_GROUP     = 0x08
	ACL_MASK      = 0x10
	ACL_OTHER     = 0x20

	// ACL entry permission bits.
	ACL_READ    = 0x04
	ACL_WRITE   = 0x02
	ACL_EXECUTE = 0x01
)

// PosixACLXattrEntry is a single entry in the userspace representation
// of a POSIX ACL. It corresponds to Linux's struct posix_acl_xattr_entry.
//
// All fields in PosixACLXattrEntry are stored as little-endian.
//
// +marshal dynamic
type PosixACLXattrEntry struct {
	_    structs.HostLayout
	Tag  uint16
	Perm uint16
	ID   uint32
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (a *PosixACLXattrEntry) SizeBytes() int {
	return 8
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (a *PosixACLXattrEntry) MarshalBytes(dst []byte) []byte {
	binary.LittleEndian.PutUint16(dst[0:], a.Tag)
	binary.LittleEndian.PutUint16(dst[2:], a.Perm)
	binary.LittleEndian.PutUint32(dst[4:], a.ID)

	return dst[8:]
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (a *PosixACLXattrEntry) UnmarshalBytes(src []byte) []byte {
	a.Tag = binary.LittleEndian.Uint16(src[0:])
	a.Perm = binary.LittleEndian.Uint16(src[2:])
	a.ID = binary.LittleEndian.Uint32(src[4:])

	return src[8:]
}

// PosixACLXattr is the userspace representation of a POSIX ACL.
//
// +marshal dynamic
type PosixACLXattr struct {
	_ structs.HostLayout

	// Version is the POSIX ACL version, stored as little-endian.
	Version uint32

	// Entries contains the ACL entries.
	Entries []PosixACLXattrEntry `hostlayout:"ignore"`
}

// posixACLXattrHeaderSize is the size in bytes of the header.
const posixACLXattrHeaderSize = 4

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (a *PosixACLXattr) SizeBytes() int {
	return posixACLXattrHeaderSize + len(a.Entries)*(*PosixACLXattrEntry)(nil).SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (a *PosixACLXattr) MarshalBytes(dst []byte) []byte {
	binary.LittleEndian.PutUint32(dst, a.Version)

	dst = dst[posixACLXattrHeaderSize:]
	for _, entry := range a.Entries {
		dst = entry.MarshalBytes(dst)
	}

	return dst
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (a *PosixACLXattr) UnmarshalBytes(src []byte) []byte {
	a.Version = binary.LittleEndian.Uint32(src)

	src = src[posixACLXattrHeaderSize:]
	for len(src) >= (*PosixACLXattrEntry)(nil).SizeBytes() {
		var entry PosixACLXattrEntry
		src = entry.UnmarshalBytes(src)
		a.Entries = append(a.Entries, entry)
	}

	return src
}
