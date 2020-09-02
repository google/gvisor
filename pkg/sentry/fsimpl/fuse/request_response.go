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

package fuse

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/tools/go_marshal/marshal"
)

// fuseInitRes is a variable-length wrapper of linux.FUSEInitOut. The FUSE
// server may implement an older version of FUSE protocol, which contains a
// linux.FUSEInitOut with less attributes.
//
// Dynamically-sized objects cannot be marshalled.
type fuseInitRes struct {
	marshal.StubMarshallable

	// initOut contains the response from the FUSE server.
	initOut linux.FUSEInitOut

	// initLen is the total length of bytes of the response.
	initLen uint32
}

// UnmarshalBytes deserializes src to the initOut attribute in a fuseInitRes.
func (r *fuseInitRes) UnmarshalBytes(src []byte) {
	out := &r.initOut

	// Introduced before FUSE kernel version 7.13.
	out.Major = uint32(usermem.ByteOrder.Uint32(src[:4]))
	src = src[4:]
	out.Minor = uint32(usermem.ByteOrder.Uint32(src[:4]))
	src = src[4:]
	out.MaxReadahead = uint32(usermem.ByteOrder.Uint32(src[:4]))
	src = src[4:]
	out.Flags = uint32(usermem.ByteOrder.Uint32(src[:4]))
	src = src[4:]
	out.MaxBackground = uint16(usermem.ByteOrder.Uint16(src[:2]))
	src = src[2:]
	out.CongestionThreshold = uint16(usermem.ByteOrder.Uint16(src[:2]))
	src = src[2:]
	out.MaxWrite = uint32(usermem.ByteOrder.Uint32(src[:4]))
	src = src[4:]

	// Introduced in FUSE kernel version 7.23.
	if len(src) >= 4 {
		out.TimeGran = uint32(usermem.ByteOrder.Uint32(src[:4]))
		src = src[4:]
	}
	// Introduced in FUSE kernel version 7.28.
	if len(src) >= 2 {
		out.MaxPages = uint16(usermem.ByteOrder.Uint16(src[:2]))
		src = src[2:]
	}
}

// SizeBytes is the size of the payload of the FUSE_INIT response.
func (r *fuseInitRes) SizeBytes() int {
	return int(r.initLen)
}
