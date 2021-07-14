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

package lisafs

import (
	"math"

	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

// Messages have two parts:
//  * A transport header used to decipher received messages.
//  * A byte array referred to as "payload" which contains the actual message.
//
// "dataLen" refers to the size of both combined.

// MID (message ID) is used to identify messages to parse from payload.
//
// +marshal slice:MIDSlice
type MID uint16

// These constants are used to identify their corresponding message types.
// Note that this order must be preserved across versions and new messages must
// only be appended at the end.
const (
	// Error is only used in responses to pass errors to client.
	Error MID = iota

	// Mount is used to establish connection and set up server side filesystem.
	Mount

	// Channel request starts a new channel.
	Channel
)

const (
	// MaxMessageSize is the largest possible message in bytes.
	MaxMessageSize uint32 = 1 << 20

	// NoUID is a sentinel used to indicate no valid UID.
	NoUID UID = math.MaxUint32

	// NoGID is a sentinel used to indicate no valid GID.
	NoGID GID = math.MaxUint32
)

// UID represents a user ID.
//
// +marshal
type UID uint32

// Ok returns true if uid is not NoUID.
func (uid UID) Ok() bool {
	return uid != NoUID
}

// GID represents a group ID.
//
// +marshal
type GID uint32

// Ok returns true if gid is not NoGID.
func (gid GID) Ok() bool {
	return gid != NoGID
}

// sockHeader is the header present in front of each message received on a UDS.
//
// +marshal
type sockHeader struct {
	size    uint32
	message MID
	_       uint16
}

// channelHeader is the header present in front of each message received on
// flipcall endpoint.
//
// +marshal
type channelHeader struct {
	message MID
	numFDs  uint8
	_       uint8
}

// SizedString represents a string in memory. The string bytes are preceded by
// a uint32 signifying the string length.
type SizedString string

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SizedString) SizeBytes() int {
	return (*primitive.Uint32)(nil).SizeBytes() + len(*s)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SizedString) MarshalBytes(dst []byte) {
	strLen := primitive.Uint32(len(*s))
	strLen.MarshalUnsafe(dst)
	dst = dst[strLen.SizeBytes():]
	// Copy without any allocation.
	copy(dst[:strLen], *s)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SizedString) UnmarshalBytes(src []byte) {
	var strLen primitive.Uint32
	strLen.UnmarshalUnsafe(src)
	src = src[strLen.SizeBytes():]
	// Take the hit, this leads to an allocation + memcpy. No way around it.
	*s = SizedString(src[:strLen])
}

// StringArray represents an array of SizedStrings in memory. The array data is
// preceded by a uint32 signifying the array length.
type StringArray []string

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *StringArray) SizeBytes() int {
	size := (*primitive.Uint32)(nil).SizeBytes()
	for _, str := range *s {
		sstr := SizedString(str)
		size += sstr.SizeBytes()
	}
	return size
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *StringArray) MarshalBytes(dst []byte) {
	arrLen := primitive.Uint32(len(*s))
	arrLen.MarshalUnsafe(dst)
	dst = dst[arrLen.SizeBytes():]
	for _, str := range *s {
		sstr := SizedString(str)
		sstr.MarshalBytes(dst)
		dst = dst[sstr.SizeBytes():]
	}
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *StringArray) UnmarshalBytes(src []byte) {
	var arrLen primitive.Uint32
	arrLen.UnmarshalUnsafe(src)
	src = src[arrLen.SizeBytes():]

	if cap(*s) < int(arrLen) {
		*s = make([]string, arrLen)
	} else {
		*s = (*s)[:arrLen]
	}

	for i := primitive.Uint32(0); i < arrLen; i++ {
		var sstr SizedString
		sstr.UnmarshalBytes(src)
		src = src[sstr.SizeBytes():]
		(*s)[i] = string(sstr)
	}
}

// Inode represents an inode on the remote filesystem.
//
// +marshal slice:InodeSlice
type Inode struct {
	ControlFD FDID
	_         uint32
	Stat      Statx
}

// MountReq represents a Mount request.
type MountReq struct {
	AttachPath SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MountReq) SizeBytes() int {
	return m.AttachPath.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MountReq) MarshalBytes(dst []byte) {
	m.AttachPath.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MountReq) UnmarshalBytes(src []byte) {
	m.AttachPath.UnmarshalBytes(src)
}

// MountResp represents a Mount response.
type MountResp struct {
	Root          Inode
	MaxM          MID
	UnsupportedMs []MID
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MountResp) SizeBytes() int {
	return m.Root.SizeBytes() +
		m.MaxM.SizeBytes() +
		(*primitive.Uint16)(nil).SizeBytes() +
		(len(m.UnsupportedMs) * (*MID)(nil).SizeBytes())
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MountResp) MarshalBytes(dst []byte) {
	m.Root.MarshalUnsafe(dst)
	dst = dst[m.Root.SizeBytes():]
	m.MaxM.MarshalUnsafe(dst)
	dst = dst[m.MaxM.SizeBytes():]
	numUnsupported := primitive.Uint16(len(m.UnsupportedMs))
	numUnsupported.MarshalBytes(dst)
	dst = dst[numUnsupported.SizeBytes():]
	MarshalUnsafeMIDSlice(m.UnsupportedMs, dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MountResp) UnmarshalBytes(src []byte) {
	m.Root.UnmarshalUnsafe(src)
	src = src[m.Root.SizeBytes():]
	m.MaxM.UnmarshalUnsafe(src)
	src = src[m.MaxM.SizeBytes():]
	var numUnsupported primitive.Uint16
	numUnsupported.UnmarshalBytes(src)
	src = src[numUnsupported.SizeBytes():]
	m.UnsupportedMs = make([]MID, numUnsupported)
	UnmarshalUnsafeMIDSlice(m.UnsupportedMs, src)
}

// ChannelResp is the response to the create channel request.
//
// +marshal
type ChannelResp struct {
	dataOffset int64
	dataLength uint64
}

// ErrorRes is returned to represent an error while handling a request.
// A field holding value 0 indicates no error on that field.
//
// +marshal
type ErrorRes struct {
	errno uint32
}

// Timespec is similar to `struct timespec` in Linux.
//
// +marshal
type Timespec struct {
	Sec  int64
	Nsec int64
}

// Statx is used to communicate stat(2) results.
//
// +marshal slice:StatxSlice
type Statx struct {
	Mask    uint32
	Mode    uint32
	Nlink   uint32
	Blksize uint32
	Dev     uint64
	Ino     uint64
	UID     UID
	GID     GID
	Rdev    uint64
	Size    uint64
	Blocks  uint64
	Atime   Timespec
	Mtime   Timespec
	Ctime   Timespec
	Btime   Timespec
}
