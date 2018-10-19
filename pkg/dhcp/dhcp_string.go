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

package dhcp

import (
	"bytes"
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
)

func (h header) String() string {
	opts, err := h.options()
	var msgtype dhcpMsgType
	if err == nil {
		msgtype, err = opts.dhcpMsgType()
	}
	if !h.isValid() || err != nil {
		return fmt.Sprintf("DHCP invalid, %v %v h[1:4]=%x cookie=%x len=%d (%v)", h.op(), h.xid(), []byte(h[1:4]), []byte(h[236:240]), len(h), err)
	}
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "%v %v len=%d\n", msgtype, h.xid(), len(h))
	fmt.Fprintf(buf, "\tciaddr:%v yiaddr:%v siaddr:%v giaddr:%v\n",
		tcpip.Address(h.ciaddr()),
		tcpip.Address(h.yiaddr()),
		tcpip.Address(h.siaddr()),
		tcpip.Address(h.giaddr()))
	fmt.Fprintf(buf, "\tchaddr:%x", h.chaddr())
	for _, opt := range opts {
		fmt.Fprintf(buf, "\n\t%v", opt)
	}
	return buf.String()
}

func (opt option) String() string {
	buf := new(bytes.Buffer)
	fmt.Fprintf(buf, "%v: ", opt.code)
	fmt.Fprintf(buf, "%x", opt.body)
	return buf.String()
}

func (code optionCode) String() string {
	switch code {
	case optSubnetMask:
		return "option(subnet-mask)"
	case optDefaultGateway:
		return "option(default-gateway)"
	case optDomainNameServer:
		return "option(dns)"
	case optDomainName:
		return "option(domain-name)"
	case optReqIPAddr:
		return "option(request-ip-address)"
	case optLeaseTime:
		return "option(lease-time)"
	case optDHCPMsgType:
		return "option(message-type)"
	case optDHCPServer:
		return "option(server)"
	case optParamReq:
		return "option(parameter-request)"
	case optMessage:
		return "option(message)"
	case optClientID:
		return "option(client-id)"
	default:
		return fmt.Sprintf("option(%d)", code)
	}
}

func (o op) String() string {
	switch o {
	case opRequest:
		return "op(request)"
	case opReply:
		return "op(reply)"
	}
	return fmt.Sprintf("op(UNKNOWN:%d)", int(o))
}

func (t dhcpMsgType) String() string {
	switch t {
	case dhcpDISCOVER:
		return "DHCPDISCOVER"
	case dhcpOFFER:
		return "DHCPOFFER"
	case dhcpREQUEST:
		return "DHCPREQUEST"
	case dhcpDECLINE:
		return "DHCPDECLINE"
	case dhcpACK:
		return "DHCPACK"
	case dhcpNAK:
		return "DHCPNAK"
	case dhcpRELEASE:
		return "DHCPRELEASE"
	}
	return fmt.Sprintf("DHCP(%d)", int(t))
}

func (v xid) String() string {
	return fmt.Sprintf("xid:%x", uint32(v))
}
