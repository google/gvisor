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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/socket/netlink/nlmsg"
	"gvisor.dev/gvisor/pkg/syserr"
)

// counter is an operation that increments a counter for the packets and number
// of bytes each time the operation is evaluated.
type counter struct {
	// Must be thread-safe because data stored here is updated for each evaluation
	// and evaluations can happen in parallel for processing multiple packets.

	bytes   atomic.Uint64 // Number of bytes that have passed through counter.
	packets atomic.Uint64 // Number of packets that have passed through counter.
}

// newCounter creates a new counter operation.
func newCounter(startBytes, startPackets uint64) *counter {
	cntr := &counter{}
	cntr.bytes.Store(startBytes)
	cntr.packets.Store(startPackets)
	return cntr
}

func (op *counter) deepCopy() operation {
	return newCounter(op.bytes.Load(), op.packets.Load())
}

// evaluate for counter increments the counter for the packet and bytes.
func (op *counter) evaluate(regs *registerSet, evalCtx opEvalCtx) {
	op.bytes.Add(uint64(evalCtx.pkt.Size()))
	op.packets.Add(1)
}

func (op *counter) GetExprName() string {
	return OpTypeCounter.String()
}

func (op *counter) Dump() ([]byte, *syserr.AnnotatedError) {
	m := &nlmsg.Message{}
	m.PutAttr(linux.NFTA_COUNTER_BYTES, nlmsg.PutU64(op.bytes.Load()))
	m.PutAttr(linux.NFTA_COUNTER_PACKETS, nlmsg.PutU64(op.packets.Load()))
	return m.Buffer(), nil
}

// checkCompatibility implements operation.checkCompatibility.
func (op *counter) checkCompatibility(cCtx *opCompatCtx) *syserr.AnnotatedError {
	return nil
}

var counterAttrPolicy = []NlaPolicy{
	linux.NFTA_COUNTER_PACKETS: NlaPolicy{nlaType: linux.NLA_U64},
	linux.NFTA_COUNTER_BYTES:   NlaPolicy{nlaType: linux.NLA_U64},
}

func initCounter(exprInfo ExprInfo) (*counter, *syserr.AnnotatedError) {
	attrs, err := NfParseWithOpts(exprInfo.ExprData, &NfParseOpts{
		Policy: counterAttrPolicy,
	})
	if err != nil {
		return nil, err
	}
	// Nftables uses 0 as the default value for both bytes and packets if the
	// attributes are not specified.
	packets, _ := AttrNetToHost[uint64](linux.NFTA_COUNTER_PACKETS, attrs)
	bytes, _ := AttrNetToHost[uint64](linux.NFTA_COUNTER_BYTES, attrs)
	return newCounter(bytes, packets), nil
}
