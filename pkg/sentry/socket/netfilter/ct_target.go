// Copyright 2026 The gVisor Authors.
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

package netfilter

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/syserr"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// CTTargetName is the name of the CT target used in the raw table for
// conntrack zone assignment.
const CTTargetName = "CT"

// ctTarget wraps stack.CTTarget for the extension system.
//
// +stateify savable
type ctTarget struct {
	stack.CTTarget
}

func (ct *ctTarget) id() targetID {
	return targetID{
		name:            CTTargetName,
		networkProtocol: ct.NetworkProtocol,
	}
}

// ctTargetMaker implements targetMaker for the CT target.
//
// +stateify savable
type ctTargetMaker struct {
	NetworkProtocol tcpip.NetworkProtocolNumber
}

func (cm *ctTargetMaker) id() targetID {
	return targetID{
		name:            CTTargetName,
		networkProtocol: cm.NetworkProtocol,
	}
}

func (*ctTargetMaker) marshal(target target) []byte {
	ct := target.(*ctTarget)
	xt := linux.XTCTTargetInfoV0{
		Target: linux.XTEntryTarget{
			TargetSize: linux.SizeOfXTCTTargetInfoV0,
		},
		Zone: ct.Zone,
	}
	copy(xt.Target.Name[:], CTTargetName)
	return marshal.Marshal(&xt)
}

func (cm *ctTargetMaker) unmarshal(buf []byte, filter stack.IPHeaderFilter) (target, *syserr.Error) {
	if len(buf) < linux.SizeOfXTCTTargetInfoV0 {
		nflog("ctTargetMaker: buf has insufficient size for CT target %d", len(buf))
		return nil, syserr.ErrInvalidArgument
	}

	var ct linux.XTCTTargetInfoV0
	ct.UnmarshalUnsafe(buf)

	return &ctTarget{CTTarget: stack.CTTarget{
		NetworkProtocol: filter.NetworkProtocol(),
		Zone:            ct.Zone,
	}}, nil
}
