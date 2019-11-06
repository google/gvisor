// Copyright 2019 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at //
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tcpip

import "gvisor.dev/gvisor/pkg/tcpip/buffer"

// A PacketBuffer contains all the data of a network packet.
//
// As a PacketBuffer traverses up the stack, it may be necessary to pass it to
// multiple endpoints. Clone() should be called in such cases so that
// modifications to the Data field do not affect other copies.
//
// +stateify savable
type PacketBuffer struct {
	// Data holds the payload of the packet. For inbound packets, it also
	// holds the headers, which are consumed as the packet moves up the
	// stack. Headers are guaranteed not to be split across views.
	//
	// The bytes backing Data are immutable, but Data itself may be trimmed
	// or otherwise modified.
	Data buffer.VectorisedView

	// The bytes backing these views are immutable. Each field may be nil
	// if either it has not been set yet or no such header exists (e.g.
	// packets sent via loopback may not have a link header).
	//
	// These fields may be Views into other Views. SR dosen't support this,
	// so deep copies are necessary in some cases.
	LinkHeader      buffer.View
	NetworkHeader   buffer.View
	TransportHeader buffer.View
}

// Clone makes a copy of pk. It clones the Data field, which creates a new
// VectorisedView but does not deep copy the underlying bytes.
func (pk PacketBuffer) Clone() PacketBuffer {
	return PacketBuffer{
		Data:            pk.Data.Clone(nil),
		LinkHeader:      pk.LinkHeader,
		NetworkHeader:   pk.NetworkHeader,
		TransportHeader: pk.TransportHeader,
	}
}
