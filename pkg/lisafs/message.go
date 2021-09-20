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
	"os"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
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
const (
	// Error is only used in responses to pass errors to client.
	Error MID = 0

	// Mount is used to establish connection between the client and server mount
	// point. lisafs requires that the client makes a successful Mount RPC before
	// making other RPCs.
	Mount MID = 1

	// Channel requests to start a new communicational channel.
	Channel MID = 2
)

const (
	// NoUID is a sentinel used to indicate no valid UID.
	NoUID UID = math.MaxUint32

	// NoGID is a sentinel used to indicate no valid GID.
	NoGID GID = math.MaxUint32
)

// MaxMessageSize is the recommended max message size that can be used by
// connections. Server implementations may choose to use other values.
func MaxMessageSize() uint32 {
	// Return HugePageSize - PageSize so that when flipcall packet window is
	// created with MaxMessageSize() + flipcall header size + channel header
	// size, HugePageSize is allocated and can be backed by a single huge page
	// if supported by the underlying memfd.
	return uint32(hostarch.HugePageSize - os.Getpagesize())
}

// TODO(gvisor.dev/issue/6450): Once this is resolved:
// * Update manual implementations and function signatures.
// * Update RPC handlers and appropriate callers to handle errors correctly.
// * Update manual implementations to get rid of buffer shifting.

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

// NoopMarshal is a noop implementation of marshal.Marshallable.MarshalBytes.
func NoopMarshal([]byte) {}

// NoopUnmarshal is a noop implementation of marshal.Marshallable.UnmarshalBytes.
func NoopUnmarshal([]byte) {}

// SizedString represents a string in memory. The marshalled string bytes are
// preceded by a uint32 signifying the string length.
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

// StringArray represents an array of SizedStrings in memory. The marshalled
// array data is preceded by a uint32 signifying the array length.
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
	_         uint32 // Need to make struct packed.
	Stat      linux.Statx
}

// MountReq represents a Mount request.
type MountReq struct {
	MountPath SizedString
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MountReq) SizeBytes() int {
	return m.MountPath.SizeBytes()
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MountReq) MarshalBytes(dst []byte) {
	m.MountPath.MarshalBytes(dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MountReq) UnmarshalBytes(src []byte) {
	m.MountPath.UnmarshalBytes(src)
}

// MountResp represents a Mount response.
type MountResp struct {
	Root Inode
	// MaxMessageSize is the maximum size of messages communicated between the
	// client and server in bytes. This includes the communication header.
	MaxMessageSize primitive.Uint32
	// SupportedMs holds all the supported messages.
	SupportedMs []MID
}

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MountResp) SizeBytes() int {
	return m.Root.SizeBytes() +
		m.MaxMessageSize.SizeBytes() +
		(*primitive.Uint16)(nil).SizeBytes() +
		(len(m.SupportedMs) * (*MID)(nil).SizeBytes())
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MountResp) MarshalBytes(dst []byte) {
	m.Root.MarshalUnsafe(dst)
	dst = dst[m.Root.SizeBytes():]
	m.MaxMessageSize.MarshalUnsafe(dst)
	dst = dst[m.MaxMessageSize.SizeBytes():]
	numSupported := primitive.Uint16(len(m.SupportedMs))
	numSupported.MarshalBytes(dst)
	dst = dst[numSupported.SizeBytes():]
	MarshalUnsafeMIDSlice(m.SupportedMs, dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MountResp) UnmarshalBytes(src []byte) {
	m.Root.UnmarshalUnsafe(src)
	src = src[m.Root.SizeBytes():]
	m.MaxMessageSize.UnmarshalUnsafe(src)
	src = src[m.MaxMessageSize.SizeBytes():]
	var numSupported primitive.Uint16
	numSupported.UnmarshalBytes(src)
	src = src[numSupported.SizeBytes():]
	m.SupportedMs = make([]MID, numSupported)
	UnmarshalUnsafeMIDSlice(m.SupportedMs, src)
}

// ChannelResp is the response to the create channel request.
//
// +marshal
type ChannelResp struct {
	dataOffset int64
	dataLength uint64
}

// ErrorResp is returned to represent an error while handling a request.
//
// +marshal
type ErrorResp struct {
	errno uint32
}
