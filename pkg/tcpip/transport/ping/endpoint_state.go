// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package ping

import (
	"gvisor.googlesource.com/gvisor/pkg/tcpip"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/buffer"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
)

// saveData saves pingPacket.data field.
func (p *pingPacket) saveData() buffer.VectorisedView {
	// We cannot save p.data directly as p.data.views may alias to p.views,
	// which is not allowed by state framework (in-struct pointer).
	return p.data.Clone(nil)
}

// loadData loads pingPacket.data field.
func (p *pingPacket) loadData(data buffer.VectorisedView) {
	// NOTE: We cannot do the p.data = data.Clone(p.views[:]) optimization
	// here because data.views is not guaranteed to be loaded by now. Plus,
	// data.views will be allocated anyway so there really is little point
	// of utilizing p.views for data.views.
	p.data = data
}

// beforeSave is invoked by stateify.
func (e *endpoint) beforeSave() {
	// Stop incoming packets from being handled (and mutate endpoint state).
	e.rcvMu.Lock()
}

// afterLoad is invoked by stateify.
func (e *endpoint) afterLoad() {
	e.stack = stack.StackFromEnv

	if e.state != stateBound && e.state != stateConnected {
		return
	}

	var err *tcpip.Error
	if e.state == stateConnected {
		e.route, err = e.stack.FindRoute(e.regNICID, e.bindAddr, e.id.RemoteAddress, e.netProto)
		if err != nil {
			panic(*err)
		}

		e.id.LocalAddress = e.route.LocalAddress
	} else if len(e.id.LocalAddress) != 0 { // stateBound
		if e.stack.CheckLocalAddress(e.regNICID, e.netProto, e.id.LocalAddress) == 0 {
			panic(tcpip.ErrBadLocalAddress)
		}
	}

	e.id, err = e.registerWithStack(e.regNICID, []tcpip.NetworkProtocolNumber{e.netProto}, e.id)
	if err != nil {
		panic(*err)
	}
}
