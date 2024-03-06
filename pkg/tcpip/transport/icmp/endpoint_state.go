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

package icmp

import (
	"context"
	"fmt"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport"
)

// saveReceivedAt is invoked by stateify.
func (p *icmpPacket) saveReceivedAt() int64 {
	return p.receivedAt.UnixNano()
}

// loadReceivedAt is invoked by stateify.
func (p *icmpPacket) loadReceivedAt(nsec int64) {
	p.receivedAt = time.Unix(0, nsec)
}

// afterLoad is invoked by stateify.
func (e *endpoint) afterLoad(ctx context.Context) {
	stack.RestoreStackFromContext(ctx).RegisterRestoredEndpoint(e)
}

// beforeSave is invoked by stateify.
func (e *endpoint) beforeSave() {
	e.freeze()
}

// Restore implements tcpip.RestoredEndpoint.Restore.
func (e *endpoint) Restore(s *stack.Stack) {
	e.thaw()

	e.net.Resume(s)

	e.stack = s
	e.ops.InitHandler(e, e.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)

	switch state := e.net.State(); state {
	case transport.DatagramEndpointStateInitial, transport.DatagramEndpointStateClosed:
	case transport.DatagramEndpointStateBound, transport.DatagramEndpointStateConnected:
		var err tcpip.Error
		info := e.net.Info()
		info.ID.LocalPort = e.ident
		info.ID, err = e.registerWithStack(info.NetProto, info.ID)
		if err != nil {
			panic(fmt.Sprintf("e.registerWithStack(%d, %#v): %s", info.NetProto, info.ID, err))
		}
		e.ident = info.ID.LocalPort
	default:
		panic(fmt.Sprintf("unhandled state = %s", state))
	}
}
