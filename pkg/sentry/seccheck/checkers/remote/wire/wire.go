// Copyright 2022 The gVisor Authors.
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

// Package wire defines structs used in the wire format for the remote checker.
package wire

// CurrentVersion is the current wire and protocol version.
const CurrentVersion = 1

// HeaderStructSize size of header struct in bytes.
const HeaderStructSize = 8

// Header is used to describe the message being sent to the remote process.
//
//	0 --------- 16 ---------- 32 ----------- 64 -----------+
//	| HeaderSize | MessageType | DroppedCount | Payload... |
//	+---- 16 ----+---- 16 -----+----- 32 -----+------------+
//
// +marshal
type Header struct {
	// HeaderSize is the size of the header in bytes. The payload comes
	// immediatelly after the header. The length is needed to allow the header to
	// expand in the future without breaking remotes that do not yet understand
	// the new fields.
	HeaderSize uint16

	// MessageType describes the payload. It must be one of the pb.MessageType
	// values and determine how the payload is interpreted. This is more efficient
	// than using protobuf.Any because Any uses the full protobuf name to identify
	// the type.
	MessageType uint16

	// DroppedCount is the number of points that failed to be written and had to
	// be dropped. It wraps around after max(uint32).
	DroppedCount uint32
}
