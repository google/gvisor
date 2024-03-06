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
	"context"
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
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

// beforeSave is invoked by stateify.
func (ep *endpoint) beforeSave() {
	ep.rcvMu.Lock()
	defer ep.rcvMu.Unlock()
	ep.rcvDisabled = true
}

// afterLoad is invoked by stateify.
func (ep *endpoint) afterLoad(ctx context.Context) {
	ep.mu.Lock()
	defer ep.mu.Unlock()

	ep.stack = stack.RestoreStackFromContext(ctx)
	ep.ops.InitHandler(ep, ep.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)

	if err := ep.stack.RegisterPacketEndpoint(ep.boundNIC, ep.boundNetProto, ep); err != nil {
		panic(fmt.Sprintf("RegisterPacketEndpoint(%d, %d, _): %s", ep.boundNIC, ep.boundNetProto, err))
	}

	ep.rcvMu.Lock()
	ep.rcvDisabled = false
	ep.rcvMu.Unlock()
}
