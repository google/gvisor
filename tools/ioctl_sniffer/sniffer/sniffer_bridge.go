// Copyright 2024 The gVisor Authors.
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

package sniffer

import (
	"encoding/binary"
	"fmt"
	"io"

	"google.golang.org/protobuf/proto"
	pb "gvisor.dev/gvisor/tools/ioctl_sniffer/ioctl_go_proto"
)

var (
	protoBytesBuf []byte
)

// ReadIoctlProto reads a single ioctl proto from the given reader. Our format is:
//   - 8 byte little endian uint64 containing the size of the proto.
//   - The proto bytes.
//
// This should match the format in sniffer_bridge.h.
func ReadIoctlProto(r io.Reader) (*pb.Ioctl, error) {
	// Read next proto from pipe.
	var protoSizeBuf [8]byte
	if _, err := io.ReadFull(r, protoSizeBuf[:]); err != nil {
		return nil, fmt.Errorf("failed to read proto size: %w", err)
	}
	protoSize := binary.LittleEndian.Uint64(protoSizeBuf[:])

	// See if we need to reallocate the buffer.
	if cap(protoBytesBuf) < int(protoSize) {
		protoBytesBuf = make([]byte, protoSize)
	} else {
		protoBytesBuf = protoBytesBuf[:protoSize]
	}
	if _, err := io.ReadFull(r, protoBytesBuf); err != nil {
		return nil, fmt.Errorf("failed to read proto data: %w", err)
	}

	// Unmarshal and parse proto.
	ioctl := &pb.Ioctl{}
	if err := proto.Unmarshal(protoBytesBuf, ioctl); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proto: %w", err)
	}

	return ioctl, nil
}
