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

package raw

import (
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// saveData saves rawPacket.data field.
func (p *rawPacket) saveData() buffer.VectorisedView {
	// We cannot save p.data directly as p.data.views may alias to p.views,
	// which is not allowed by state framework (in-struct pointer).
	return p.data.Clone(nil)
}

// loadData loads rawPacket.data field.
func (p *rawPacket) loadData(data buffer.VectorisedView) {
	// NOTE: We cannot do the p.data = data.Clone(p.views[:]) optimization
	// here because data.views is not guaranteed to be loaded by now. Plus,
	// data.views will be allocated anyway so there really is little point
	// of utilizing p.views for data.views.
	p.data = data
}

// beforeSave is invoked by stateify.
func (ep *endpoint) beforeSave() {
	// Stop incoming packets from being handled (and mutate endpoint state).
	// The lock will be released after saveRcvBufSizeMax(), which would have
	// saved ep.rcvBufSizeMax and set it to 0 to continue blocking incoming
	// packets.
	ep.rcvMu.Lock()
}

// saveRcvBufSizeMax is invoked by stateify.
func (ep *endpoint) saveRcvBufSizeMax() int {
	max := ep.rcvBufSizeMax
	// Make sure no new packets will be handled regardless of the lock.
	ep.rcvBufSizeMax = 0
	// Release the lock acquired in beforeSave() so regular endpoint closing
	// logic can proceed after save.
	ep.rcvMu.Unlock()
	return max
}

// loadRcvBufSizeMax is invoked by stateify.
func (ep *endpoint) loadRcvBufSizeMax(max int) {
	ep.rcvBufSizeMax = max
}

// afterLoad is invoked by stateify.
func (ep *endpoint) afterLoad() {
	stack.StackFromEnv.RegisterRestoredEndpoint(ep)
}

// Resume implements tcpip.ResumableEndpoint.Resume.
func (ep *endpoint) Resume(s *stack.Stack) {
	ep.stack = s

	// If the endpoint is connected, re-connect.
	if ep.connected {
		var err *tcpip.Error
		ep.route, err = ep.stack.FindRoute(ep.RegisterNICID, ep.BindAddr, ep.route.RemoteAddress, ep.NetProto, false)
		if err != nil {
			panic(err)
		}
	}

	// If the endpoint is bound, re-bind.
	if ep.bound {
		if ep.stack.CheckLocalAddress(ep.RegisterNICID, ep.NetProto, ep.BindAddr) == 0 {
			panic(tcpip.ErrBadLocalAddress)
		}
	}

	if ep.associated {
		if err := ep.stack.RegisterRawTransportEndpoint(ep.RegisterNICID, ep.NetProto, ep.TransProto, ep); err != nil {
			panic(err)
		}
	}
}
