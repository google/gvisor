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

	"gvisor.dev/gvisor/pkg/marshal"
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
//
// +marshal dynamic
type SizedString struct {
	Str string
}

var _ marshal.Marshallable = (*SizedString)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (s *SizedString) SizeBytes() int {
	return (*primitive.Uint32)(nil).SizeBytes() + len(s.Str)
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (s *SizedString) MarshalBytes(dst []byte) {
	strLen := primitive.Uint32(len(s.Str))
	strLen.MarshalBytes(dst)
	dst = dst[strLen.SizeBytes():]
	// Copy without any allocation.
	copy(dst[:strLen], s.Str)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (s *SizedString) UnmarshalBytes(src []byte) {
	var strLen primitive.Uint32
	strLen.UnmarshalBytes(src)
	src = src[strLen.SizeBytes():]
	// Take the hit, this leads to an allocation + memcpy. No way around it.
	s.Str = string(src[:strLen])
}

// MountReq represents a Mount request.
//
// +marshal dynamic
type MountReq struct {
	MountPath SizedString
}

var _ marshal.Marshallable = (*MountReq)(nil)

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
//
// +marshal dynamic
type MountResp struct {
	Root           FDID
	MaxM           MID
	NumUnsupported primitive.Uint16
	UnsupportedMs  []MID
}

var _ marshal.Marshallable = (*MountResp)(nil)

// SizeBytes implements marshal.Marshallable.SizeBytes.
func (m *MountResp) SizeBytes() int {
	return m.Root.SizeBytes() +
		m.MaxM.SizeBytes() +
		m.NumUnsupported.SizeBytes() +
		(len(m.UnsupportedMs) * (*MID)(nil).SizeBytes())
}

// MarshalBytes implements marshal.Marshallable.MarshalBytes.
func (m *MountResp) MarshalBytes(dst []byte) {
	m.Root.MarshalBytes(dst)
	dst = dst[m.Root.SizeBytes():]
	m.MaxM.MarshalBytes(dst)
	dst = dst[m.MaxM.SizeBytes():]
	m.NumUnsupported.MarshalBytes(dst)
	dst = dst[m.NumUnsupported.SizeBytes():]
	MarshalUnsafeMIDSlice(m.UnsupportedMs, dst)
}

// UnmarshalBytes implements marshal.Marshallable.UnmarshalBytes.
func (m *MountResp) UnmarshalBytes(src []byte) {
	m.Root.UnmarshalBytes(src)
	src = src[m.Root.SizeBytes():]
	m.MaxM.UnmarshalBytes(src)
	src = src[m.MaxM.SizeBytes():]
	m.NumUnsupported.UnmarshalBytes(src)
	src = src[m.NumUnsupported.SizeBytes():]
	m.UnsupportedMs = make([]MID, m.NumUnsupported)
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
