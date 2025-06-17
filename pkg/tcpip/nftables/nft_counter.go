// Copyright 2025 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nftables

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// counter is an operation that increments a counter for the packets and number
// of bytes each time the operation is evaluated.
type counter struct {
	// Must be thread-safe because data stored here is updated for each evaluation
	// and evaluations can happen in parallel for processing multiple packets.

	bytes   atomic.Int64 // Number of bytes that have passed through counter.
	packets atomic.Int64 // Number of packets that have passed through counter.
}

// newCounter creates a new counter operation.
func newCounter(startBytes, startPackets int64) *counter {
	cntr := &counter{}
	cntr.bytes.Store(startBytes)
	cntr.packets.Store(startPackets)
	return cntr
}

// evaluate for counter increments the counter for the packet and bytes.
func (op *counter) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	op.bytes.Add(int64(pkt.Size()))
	op.packets.Add(1)
}
