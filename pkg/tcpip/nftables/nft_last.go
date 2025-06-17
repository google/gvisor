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

// last is an operation that records the last time the operation was evaluated
// for the purpose of tracking the last time the rule has matched a packet.
// Note: no explicit constructor bc no fields need to be set (use &last{}).
type last struct {
	// Must be thread-safe because data stored here is updated for each evaluation
	// and evaluations can happen in parallel for processing multiple packets.

	// timestampMS is the time of last evaluation as a millisecond unix time.
	// Milliseconds chosen as units because closest in magnitude to jiffies.
	timestampMS atomic.Int64

	// set is whether the operation has been evaluated at least once.
	set atomic.Bool

	// Note: The last operation has not been observed in the nft binary debug
	// output, so it has no interpretation, though it is fully implemented.
}

// evaluate for last records the last time the operation was evaluated and flags
// if this was the first time the operation was evaluated.
func (op *last) evaluate(regs *registerSet, pkt *stack.PacketBuffer, rule *Rule) {
	clock := rule.chain.table.afFilter.nftState.clock
	op.timestampMS.Store(clock.Now().UnixMilli())
	op.set.CompareAndSwap(false, true)
}
