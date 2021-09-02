// Copyright 2018 The gVisor Authors.
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

package packet

import (
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// saveReceivedAt is invoked by stateify.
func (p *packet) saveReceivedAt() int64 {
	return p.receivedAt.UnixNano()
}

// loadReceivedAt is invoked by stateify.
func (p *packet) loadReceivedAt(nsec int64) {
	p.receivedAt = time.Unix(0, nsec)
}

// saveData saves packet.data field.
func (p *packet) saveData() buffer.VectorisedView {
	return p.data.Clone(nil)
}

// loadData loads packet.data field.
func (p *packet) loadData(data buffer.VectorisedView) {
	p.data = data
}

// beforeSave is invoked by stateify.
func (ep *endpoint) beforeSave() {
	ep.freeze()
}

// afterLoad is invoked by stateify.
func (ep *endpoint) afterLoad() {
	ep.thaw()
	ep.stack = stack.StackFromEnv
	ep.ops.InitHandler(ep, ep.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)

	// TODO(gvisor.dev/173): Once bind is supported, choose the right NIC.
	if err := ep.stack.RegisterPacketEndpoint(0, ep.netProto, ep); err != nil {
		panic(err)
	}
}
