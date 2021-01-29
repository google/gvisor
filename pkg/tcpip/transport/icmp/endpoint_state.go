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
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// saveData saves icmpPacket.data field.
func (p *icmpPacket) saveData() buffer.VectorisedView {
	// We cannot save p.data directly as p.data.views may alias to p.views,
	// which is not allowed by state framework (in-struct pointer).
	return p.data.Clone(nil)
}

// loadData loads icmpPacket.data field.
func (p *icmpPacket) loadData(data buffer.VectorisedView) {
	// NOTE: We cannot do the p.data = data.Clone(p.views[:]) optimization
	// here because data.views is not guaranteed to be loaded by now. Plus,
	// data.views will be allocated anyway so there really is little point
	// of utilizing p.views for data.views.
	p.data = data
}

// beforeSave is invoked by stateify.
func (e *endpoint) beforeSave() {
	// Stop incoming packets from being handled (and mutate endpoint state).
	// The lock will be released after savercvBufSizeMax(), which would have
	// saved e.rcvBufSizeMax and set it to 0 to continue blocking incoming
	// packets.
	e.rcvMu.Lock()
}

// saveRcvBufSizeMax is invoked by stateify.
func (e *endpoint) saveRcvBufSizeMax() int {
	max := e.rcvBufSizeMax
	// Make sure no new packets will be handled regardless of the lock.
	e.rcvBufSizeMax = 0
	// Release the lock acquired in beforeSave() so regular endpoint closing
	// logic can proceed after save.
	e.rcvMu.Unlock()
	return max
}

// loadRcvBufSizeMax is invoked by stateify.
func (e *endpoint) loadRcvBufSizeMax(max int) {
	e.rcvBufSizeMax = max
}

// afterLoad is invoked by stateify.
func (e *endpoint) afterLoad() {
	stack.StackFromEnv.RegisterRestoredEndpoint(e)
}

// Resume implements tcpip.ResumableEndpoint.Resume.
func (e *endpoint) Resume(s *stack.Stack) {
	e.stack = s
	e.ops.InitHandler(e, e.stack, tcpip.GetStackSendBufferLimits)

	if e.state != stateBound && e.state != stateConnected {
		return
	}

	var err tcpip.Error
	if e.state == stateConnected {
		e.route, err = e.stack.FindRoute(e.RegisterNICID, e.BindAddr, e.ID.RemoteAddress, e.NetProto, false /* multicastLoop */)
		if err != nil {
			panic(err)
		}

		e.ID.LocalAddress = e.route.LocalAddress
	} else if len(e.ID.LocalAddress) != 0 { // stateBound
		if e.stack.CheckLocalAddress(e.RegisterNICID, e.NetProto, e.ID.LocalAddress) == 0 {
			panic(&tcpip.ErrBadLocalAddress{})
		}
	}

	e.ID, err = e.registerWithStack(e.RegisterNICID, []tcpip.NetworkProtocolNumber{e.NetProto}, e.ID)
	if err != nil {
		panic(err)
	}
}
