// Copyright 2018 Google LLC
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

package udp

import (
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/header"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
)

// saveData saves udpPacket.data field.
func (u *udpPacket) saveData() buffer.VectorisedView {
	// We cannot save u.data directly as u.data.views may alias to u.views,
	// which is not allowed by state framework (in-struct pointer).
	return u.data.Clone(nil)
}

// loadData loads udpPacket.data field.
func (u *udpPacket) loadData(data buffer.VectorisedView) {
	// NOTE: We cannot do the u.data = data.Clone(u.views[:]) optimization
	// here because data.views is not guaranteed to be loaded by now. Plus,
	// data.views will be allocated anyway so there really is little point
	// of utilizing u.views for data.views.
	u.data = data
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
	e.stack = stack.StackFromEnv

	if e.state != stateBound && e.state != stateConnected {
		return
	}

	netProto := e.effectiveNetProtos[0]
	// Connect() and bindLocked() both assert
	//
	//     netProto == header.IPv6ProtocolNumber
	//
	// before creating a multi-entry effectiveNetProtos.
	if len(e.effectiveNetProtos) > 1 {
		netProto = header.IPv6ProtocolNumber
	}

	var err *tcpip.Error
	if e.state == stateConnected {
		e.route, err = e.stack.FindRoute(e.regNICID, e.id.LocalAddress, e.id.RemoteAddress, netProto, e.multicastLoop)
		if err != nil {
			panic(*err)
		}

		e.id.LocalAddress = e.route.LocalAddress
	} else if len(e.id.LocalAddress) != 0 { // stateBound
		if e.stack.CheckLocalAddress(e.regNICID, netProto, e.id.LocalAddress) == 0 {
			panic(tcpip.ErrBadLocalAddress)
		}
	}

	// Our saved state had a port, but we don't actually have a
	// reservation. We need to remove the port from our state, but still
	// pass it to the reservation machinery.
	id := e.id
	e.id.LocalPort = 0
	e.id, err = e.registerWithStack(e.regNICID, e.effectiveNetProtos, id)
	if err != nil {
		panic(*err)
	}

	for _, m := range e.multicastMemberships {
		if err := e.stack.JoinGroup(e.netProto, m.nicID, m.multicastAddr); err != nil {
			panic(err)
		}
	}
}
