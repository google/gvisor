// Copyright 2018 Google Inc.
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

// Package dhcp implements a DHCP client and server as described in RFC 2131.
package dhcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"gvisor.googlesource.com/gvisor/pkg/tcpip"
)

// Config is standard DHCP configuration.
type Config struct {
	ServerAddress    tcpip.Address     // address of the server
	SubnetMask       tcpip.AddressMask // client address subnet mask
	Gateway          tcpip.Address     // client default gateway
	DomainNameServer tcpip.Address     // client domain name server
	LeaseLength      time.Duration     // length of the address lease
}

func (cfg *Config) decode(opts []option) error {
	*cfg = Config{}
	for _, opt := range opts {
		b := opt.body
		if l := opt.code.len(); l != -1 && l != len(b) {
			return fmt.Errorf("%s bad length: %d", opt.code, len(b))
		}
		switch opt.code {
		case optLeaseTime:
			t := binary.BigEndian.Uint32(b)
			cfg.LeaseLength = time.Duration(t) * time.Second
		case optSubnetMask:
			cfg.SubnetMask = tcpip.AddressMask(b)
		case optDHCPServer:
			cfg.ServerAddress = tcpip.Address(b)
		case optDefaultGateway:
			cfg.Gateway = tcpip.Address(b)
		case optDomainNameServer:
			cfg.DomainNameServer = tcpip.Address(b)
		}
	}
	return nil
}

func (cfg Config) encode() (opts []option) {
	if cfg.ServerAddress != "" {
		opts = append(opts, option{optDHCPServer, []byte(cfg.ServerAddress)})
	}
	if cfg.SubnetMask != "" {
		opts = append(opts, option{optSubnetMask, []byte(cfg.SubnetMask)})
	}
	if cfg.Gateway != "" {
		opts = append(opts, option{optDefaultGateway, []byte(cfg.Gateway)})
	}
	if cfg.DomainNameServer != "" {
		opts = append(opts, option{optDomainNameServer, []byte(cfg.DomainNameServer)})
	}
	if l := cfg.LeaseLength / time.Second; l != 0 {
		v := make([]byte, 4)
		v[0] = byte(l >> 24)
		v[1] = byte(l >> 16)
		v[2] = byte(l >> 8)
		v[3] = byte(l >> 0)
		opts = append(opts, option{optLeaseTime, v})
	}
	return opts
}

const (
	serverPort = 67
	clientPort = 68
)

var magicCookie = []byte{99, 130, 83, 99} // RFC 1497

type xid uint32

type header []byte

func (h header) init() {
	h[1] = 0x01       // htype
	h[2] = 0x06       // hlen
	h[3] = 0x00       // hops
	h[8], h[9] = 0, 0 // secs
	copy(h[236:240], magicCookie)
}

func (h header) isValid() bool {
	if len(h) < 241 {
		return false
	}
	if o := h.op(); o != opRequest && o != opReply {
		return false
	}
	if h[1] != 0x01 || h[2] != 0x06 || h[3] != 0x00 {
		return false
	}
	return bytes.Equal(h[236:240], magicCookie) && h[len(h)-1] == 0
}

func (h header) op() op           { return op(h[0]) }
func (h header) setOp(o op)       { h[0] = byte(o) }
func (h header) xidbytes() []byte { return h[4:8] }
func (h header) xid() xid         { return xid(h[4])<<24 | xid(h[5])<<16 | xid(h[6])<<8 | xid(h[7]) }
func (h header) setBroadcast()    { h[10], h[11] = 0x80, 0x00 } // flags top bit
func (h header) ciaddr() []byte   { return h[12:16] }
func (h header) yiaddr() []byte   { return h[16:20] }
func (h header) siaddr() []byte   { return h[20:24] }
func (h header) giaddr() []byte   { return h[24:28] }
func (h header) chaddr() []byte   { return h[28:44] }
func (h header) sname() []byte    { return h[44:108] }
func (h header) file() []byte     { return h[108:236] }

func (h header) options() (opts options, err error) {
	i := headerBaseSize
	for i < len(h) {
		if h[i] == 0 {
			i++
			continue
		}
		if h[i] == 255 {
			break
		}
		if len(h) <= i+1 {
			return nil, fmt.Errorf("option missing length")
		}
		optlen := int(h[i+1])
		if len(h) < i+2+optlen {
			return nil, fmt.Errorf("option too long")
		}
		opts = append(opts, option{
			code: optionCode(h[i]),
			body: h[i+2 : i+2+optlen],
		})
		i += 2 + optlen
	}
	return opts, nil
}

func (h header) setOptions(opts []option) {
	i := headerBaseSize
	for _, opt := range opts {
		h[i] = byte(opt.code)
		h[i+1] = byte(len(opt.body))
		copy(h[i+2:i+2+len(opt.body)], opt.body)
		i += 2 + len(opt.body)
	}
	for ; i < len(h); i++ {
		h[i] = 0
	}
}

// headerBaseSize is the size of a DHCP packet, including the magic cookie.
//
// Note that a DHCP packet is required to have an 'end' option that takes
// up an extra byte, so the minimum DHCP packet size is headerBaseSize + 1.
const headerBaseSize = 240

type option struct {
	code optionCode
	body []byte
}

type optionCode byte

const (
	optSubnetMask       optionCode = 1
	optDefaultGateway   optionCode = 3
	optDomainNameServer optionCode = 6
	optReqIPAddr        optionCode = 50
	optLeaseTime        optionCode = 51
	optDHCPMsgType      optionCode = 53 // dhcpMsgType
	optDHCPServer       optionCode = 54
	optParamReq         optionCode = 55
)

func (code optionCode) len() int {
	switch code {
	case optSubnetMask, optDefaultGateway, optDomainNameServer,
		optReqIPAddr, optLeaseTime, optDHCPServer:
		return 4
	case optDHCPMsgType:
		return 1
	case optParamReq:
		return -1 // no fixed length
	default:
		return -1
	}
}

func (code optionCode) String() string {
	switch code {
	case optSubnetMask:
		return "option(subnet-mask)"
	case optDefaultGateway:
		return "option(default-gateway)"
	case optDomainNameServer:
		return "option(dns)"
	case optReqIPAddr:
		return "option(request-ip-address)"
	case optLeaseTime:
		return "option(least-time)"
	case optDHCPMsgType:
		return "option(message-type)"
	case optDHCPServer:
		return "option(server)"
	case optParamReq:
		return "option(parameter-request)"
	default:
		return fmt.Sprintf("option(%d)", code)
	}
}

type options []option

func (opts options) dhcpMsgType() (dhcpMsgType, error) {
	for _, opt := range opts {
		if opt.code == optDHCPMsgType {
			if len(opt.body) != 1 {
				return 0, fmt.Errorf("%s: bad length: %d", optDHCPMsgType, len(opt.body))
			}
			v := opt.body[0]
			if v <= 0 || v >= 8 {
				return 0, fmt.Errorf("%s: unknown value: %d", optDHCPMsgType, v)
			}
			return dhcpMsgType(v), nil
		}
	}
	return 0, nil
}

func (opts options) len() int {
	l := 0
	for _, opt := range opts {
		l += 1 + 1 + len(opt.body) // code + len + body
	}
	return l + 1 // extra byte for 'pad' option
}

type op byte

const (
	opRequest op = 0x01
	opReply   op = 0x02
)

// dhcpMsgType is the DHCP Message Type from RFC 1533, section 9.4.
type dhcpMsgType byte

const (
	dhcpDISCOVER dhcpMsgType = 1
	dhcpOFFER    dhcpMsgType = 2
	dhcpREQUEST  dhcpMsgType = 3
	dhcpDECLINE  dhcpMsgType = 4
	dhcpACK      dhcpMsgType = 5
	dhcpNAK      dhcpMsgType = 6
	dhcpRELEASE  dhcpMsgType = 7
)
