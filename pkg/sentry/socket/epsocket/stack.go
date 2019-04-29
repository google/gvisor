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

package epsocket

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/inet"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/stack"
	"gvisor.googlesource.com/gvisor/pkg/tcpip/transport/tcp"
)

// Stack implements inet.Stack for netstack/tcpip/stack.Stack.
//
// +stateify savable
type Stack struct {
	Stack *stack.Stack `state:"manual"`
}

// SupportsIPv6 implements Stack.SupportsIPv6.
func (s *Stack) SupportsIPv6() bool {
	return s.Stack.CheckNetworkProtocol(ipv6.ProtocolNumber)
}

// Interfaces implements inet.Stack.Interfaces.
func (s *Stack) Interfaces() map[int32]inet.Interface {
	is := make(map[int32]inet.Interface)
	for id, ni := range s.Stack.NICInfo() {
		var devType uint16
		if ni.Flags.Loopback {
			devType = linux.ARPHRD_LOOPBACK
		}
		is[int32(id)] = inet.Interface{
			Name:       ni.Name,
			Addr:       []byte(ni.LinkAddress),
			Flags:      uint32(nicStateFlagsToLinux(ni.Flags)),
			DeviceType: devType,
			MTU:        ni.MTU,
		}
	}
	return is
}

// InterfaceAddrs implements inet.Stack.InterfaceAddrs.
func (s *Stack) InterfaceAddrs() map[int32][]inet.InterfaceAddr {
	nicAddrs := make(map[int32][]inet.InterfaceAddr)
	for id, ni := range s.Stack.NICInfo() {
		var addrs []inet.InterfaceAddr
		for _, a := range ni.ProtocolAddresses {
			var family uint8
			switch a.Protocol {
			case ipv4.ProtocolNumber:
				family = linux.AF_INET
			case ipv6.ProtocolNumber:
				family = linux.AF_INET6
			default:
				log.Warningf("Unknown network protocol in %+v", a)
				continue
			}

			addrs = append(addrs, inet.InterfaceAddr{
				Family:    family,
				PrefixLen: uint8(len(a.Address) * 8),
				Addr:      []byte(a.Address),
				// TODO(b/68878065): Other fields.
			})
		}
		nicAddrs[int32(id)] = addrs
	}
	return nicAddrs
}

// TCPReceiveBufferSize implements inet.Stack.TCPReceiveBufferSize.
func (s *Stack) TCPReceiveBufferSize() (inet.TCPBufferSize, error) {
	var rs tcp.ReceiveBufferSizeOption
	err := s.Stack.TransportProtocolOption(tcp.ProtocolNumber, &rs)
	return inet.TCPBufferSize{
		Min:     rs.Min,
		Default: rs.Default,
		Max:     rs.Max,
	}, syserr.TranslateNetstackError(err).ToError()
}

// SetTCPReceiveBufferSize implements inet.Stack.SetTCPReceiveBufferSize.
func (s *Stack) SetTCPReceiveBufferSize(size inet.TCPBufferSize) error {
	rs := tcp.ReceiveBufferSizeOption{
		Min:     size.Min,
		Default: size.Default,
		Max:     size.Max,
	}
	return syserr.TranslateNetstackError(s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, rs)).ToError()
}

// TCPSendBufferSize implements inet.Stack.TCPSendBufferSize.
func (s *Stack) TCPSendBufferSize() (inet.TCPBufferSize, error) {
	var ss tcp.SendBufferSizeOption
	err := s.Stack.TransportProtocolOption(tcp.ProtocolNumber, &ss)
	return inet.TCPBufferSize{
		Min:     ss.Min,
		Default: ss.Default,
		Max:     ss.Max,
	}, syserr.TranslateNetstackError(err).ToError()
}

// SetTCPSendBufferSize implements inet.Stack.SetTCPSendBufferSize.
func (s *Stack) SetTCPSendBufferSize(size inet.TCPBufferSize) error {
	ss := tcp.SendBufferSizeOption{
		Min:     size.Min,
		Default: size.Default,
		Max:     size.Max,
	}
	return syserr.TranslateNetstackError(s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, ss)).ToError()
}

// TCPSACKEnabled implements inet.Stack.TCPSACKEnabled.
func (s *Stack) TCPSACKEnabled() (bool, error) {
	var sack tcp.SACKEnabled
	err := s.Stack.TransportProtocolOption(tcp.ProtocolNumber, &sack)
	return bool(sack), syserr.TranslateNetstackError(err).ToError()
}

// SetTCPSACKEnabled implements inet.Stack.SetTCPSACKEnabled.
func (s *Stack) SetTCPSACKEnabled(enabled bool) error {
	return syserr.TranslateNetstackError(s.Stack.SetTransportProtocolOption(tcp.ProtocolNumber, tcp.SACKEnabled(enabled))).ToError()
}
