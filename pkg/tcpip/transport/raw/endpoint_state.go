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

// afterLoad is invoked by stateify.
func (e *endpoint) afterLoad() {
	stack.StackFromEnv.RegisterRestoredEndpoint(e)
}

// beforeSave is invoked by stateify.
func (e *endpoint) beforeSave() {
	e.freeze()
}

// Resume implements tcpip.ResumableEndpoint.Resume.
func (e *endpoint) Resume(s *stack.Stack) {
	e.thaw()
	e.stack = s
	e.ops.InitHandler(e, e.stack, tcpip.GetStackSendBufferLimits, tcpip.GetStackReceiveBufferLimits)

	// If the endpoint is connected, re-connect.
	if e.connected {
		var err tcpip.Error
		// TODO(gvisor.dev/issue/4906): Properly restore the route with the right
		// remote address. We used to pass e.remote.RemoteAddress which was
		// effectively the empty address but since moving e.route to hold a pointer
		// to a route instead of the route by value, we pass the empty address
		// directly. Obviously this was always wrong since we should provide the
		// remote address we were connected to, to properly restore the route.
		e.route, err = e.stack.FindRoute(e.RegisterNICID, e.BindAddr, "", e.NetProto, false)
		if err != nil {
			panic(err)
		}
	}

	// If the endpoint is bound, re-bind.
	if e.bound {
		if e.stack.CheckLocalAddress(e.RegisterNICID, e.NetProto, e.BindAddr) == 0 {
			panic(&tcpip.ErrBadLocalAddress{})
		}
	}

	if e.associated {
		if err := e.stack.RegisterRawTransportEndpoint(e.NetProto, e.TransProto, e); err != nil {
			panic(err)
		}
	}
}
