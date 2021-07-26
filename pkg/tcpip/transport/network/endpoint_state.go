// Copyright 2021 The gVisor Authors.
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

package network

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Resume implements tcpip.ResumableEndpoint.Resume.
func (e *Endpoint) Resume(s *stack.Stack) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.stack = s

	for m := range e.multicastMemberships {
		if err := e.stack.JoinGroup(e.NetProto, m.nicID, m.multicastAddr); err != nil {
			panic(err)
		}
	}

	state := e.EndpointState()
	if state != StateBound && state != StateConnected {
		return
	}

	if state == StateConnected {
		var err tcpip.Error
		e.route, err = e.stack.FindRoute(e.RegisterNICID, e.ID.LocalAddress, e.ID.RemoteAddress, e.effectiveNetProto, e.ops.GetMulticastLoop())
		if err != nil {
			panic(err)
		}
	} else if len(e.ID.LocalAddress) != 0 && !e.isBroadcastOrMulticast(e.RegisterNICID, e.effectiveNetProto, e.ID.LocalAddress) { // stateBound
		// A local unicast address is specified, verify that it's valid.
		if e.stack.CheckLocalAddress(e.RegisterNICID, e.effectiveNetProto, e.ID.LocalAddress) == 0 {
			panic(&tcpip.ErrBadLocalAddress{})
		}
	}
}
