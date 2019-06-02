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

package hostinet

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/binary"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/inet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

var defaultRecvBufSize = inet.TCPBufferSize{
	Min:     4096,
	Default: 87380,
	Max:     6291456,
}

var defaultSendBufSize = inet.TCPBufferSize{
	Min:     4096,
	Default: 16384,
	Max:     4194304,
}

// Stack implements inet.Stack for host sockets.
type Stack struct {
	// Stack is immutable.
	interfaces     map[int32]inet.Interface
	interfaceAddrs map[int32][]inet.InterfaceAddr
	supportsIPv6   bool
	tcpRecvBufSize inet.TCPBufferSize
	tcpSendBufSize inet.TCPBufferSize
	tcpSACKEnabled bool
}

// NewStack returns an empty Stack containing no configuration.
func NewStack() *Stack {
	return &Stack{
		interfaces:     make(map[int32]inet.Interface),
		interfaceAddrs: make(map[int32][]inet.InterfaceAddr),
	}
}

// Configure sets up the stack using the current state of the host network.
func (s *Stack) Configure() error {
	if err := addHostInterfaces(s); err != nil {
		return err
	}

	if _, err := os.Stat("/proc/net/if_inet6"); err == nil {
		s.supportsIPv6 = true
	}

	s.tcpRecvBufSize = defaultRecvBufSize
	if tcpRMem, err := readTCPBufferSizeFile("/proc/sys/net/ipv4/tcp_rmem"); err == nil {
		s.tcpRecvBufSize = tcpRMem
	} else {
		log.Warningf("Failed to read TCP receive buffer size, using default values")
	}

	s.tcpSendBufSize = defaultSendBufSize
	if tcpWMem, err := readTCPBufferSizeFile("/proc/sys/net/ipv4/tcp_wmem"); err == nil {
		s.tcpSendBufSize = tcpWMem
	} else {
		log.Warningf("Failed to read TCP send buffer size, using default values")
	}

	// SACK is important for performance and even compatibility, assume it's
	// enabled if we can't find the actual value.
	s.tcpSACKEnabled = true
	if sack, err := ioutil.ReadFile("/proc/sys/net/ipv4/tcp_sack"); err == nil {
		s.tcpSACKEnabled = strings.TrimSpace(string(sack)) != "0"
	} else {
		log.Warningf("Failed to read if TCP SACK if enabled, setting to true")
	}

	return nil
}

// ExtractHostInterfaces will populate an interface map and
// interfaceAddrs map with the results of the equivalent
// netlink messages.
func ExtractHostInterfaces(links []syscall.NetlinkMessage, addrs []syscall.NetlinkMessage, interfaces map[int32]inet.Interface, interfaceAddrs map[int32][]inet.InterfaceAddr) error {
	for _, link := range links {
		if link.Header.Type != syscall.RTM_NEWLINK {
			continue
		}
		if len(link.Data) < syscall.SizeofIfInfomsg {
			return fmt.Errorf("RTM_GETLINK returned RTM_NEWLINK message with invalid data length (%d bytes, expected at least %d bytes)", len(link.Data), syscall.SizeofIfInfomsg)
		}
		var ifinfo syscall.IfInfomsg
		binary.Unmarshal(link.Data[:syscall.SizeofIfInfomsg], usermem.ByteOrder, &ifinfo)
		inetIF := inet.Interface{
			DeviceType: ifinfo.Type,
			Flags:      ifinfo.Flags,
		}
		// Not clearly documented: syscall.ParseNetlinkRouteAttr will check the
		// syscall.NetlinkMessage.Header.Type and skip the struct ifinfomsg
		// accordingly.
		attrs, err := syscall.ParseNetlinkRouteAttr(&link)
		if err != nil {
			return fmt.Errorf("RTM_GETLINK returned RTM_NEWLINK message with invalid rtattrs: %v", err)
		}
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case syscall.IFLA_ADDRESS:
				inetIF.Addr = attr.Value
			case syscall.IFLA_IFNAME:
				inetIF.Name = string(attr.Value[:len(attr.Value)-1])
			}
		}
		interfaces[ifinfo.Index] = inetIF
	}

	for _, addr := range addrs {
		if addr.Header.Type != syscall.RTM_NEWADDR {
			continue
		}
		if len(addr.Data) < syscall.SizeofIfAddrmsg {
			return fmt.Errorf("RTM_GETADDR returned RTM_NEWADDR message with invalid data length (%d bytes, expected at least %d bytes)", len(addr.Data), syscall.SizeofIfAddrmsg)
		}
		var ifaddr syscall.IfAddrmsg
		binary.Unmarshal(addr.Data[:syscall.SizeofIfAddrmsg], usermem.ByteOrder, &ifaddr)
		inetAddr := inet.InterfaceAddr{
			Family:    ifaddr.Family,
			PrefixLen: ifaddr.Prefixlen,
			Flags:     ifaddr.Flags,
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&addr)
		if err != nil {
			return fmt.Errorf("RTM_GETADDR returned RTM_NEWADDR message with invalid rtattrs: %v", err)
		}
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case syscall.IFA_ADDRESS:
				inetAddr.Addr = attr.Value
			}
		}
		interfaceAddrs[int32(ifaddr.Index)] = append(interfaceAddrs[int32(ifaddr.Index)], inetAddr)
	}

	return nil
}

func addHostInterfaces(s *Stack) error {
	links, err := doNetlinkRouteRequest(syscall.RTM_GETLINK)
	if err != nil {
		return fmt.Errorf("RTM_GETLINK failed: %v", err)
	}

	addrs, err := doNetlinkRouteRequest(syscall.RTM_GETADDR)
	if err != nil {
		return fmt.Errorf("RTM_GETADDR failed: %v", err)
	}

	return ExtractHostInterfaces(links, addrs, s.interfaces, s.interfaceAddrs)
}

func doNetlinkRouteRequest(req int) ([]syscall.NetlinkMessage, error) {
	data, err := syscall.NetlinkRIB(req, syscall.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	return syscall.ParseNetlinkMessage(data)
}

func readTCPBufferSizeFile(filename string) (inet.TCPBufferSize, error) {
	contents, err := ioutil.ReadFile(filename)
	if err != nil {
		return inet.TCPBufferSize{}, fmt.Errorf("failed to read %s: %v", filename, err)
	}
	ioseq := usermem.BytesIOSequence(contents)
	fields := make([]int32, 3)
	if n, err := usermem.CopyInt32StringsInVec(context.Background(), ioseq.IO, ioseq.Addrs, fields, ioseq.Opts); n != ioseq.NumBytes() || err != nil {
		return inet.TCPBufferSize{}, fmt.Errorf("failed to parse %s (%q): got %v after %d/%d bytes", filename, contents, err, n, ioseq.NumBytes())
	}
	return inet.TCPBufferSize{
		Min:     int(fields[0]),
		Default: int(fields[1]),
		Max:     int(fields[2]),
	}, nil
}

// Interfaces implements inet.Stack.Interfaces.
func (s *Stack) Interfaces() map[int32]inet.Interface {
	return s.interfaces
}

// InterfaceAddrs implements inet.Stack.InterfaceAddrs.
func (s *Stack) InterfaceAddrs() map[int32][]inet.InterfaceAddr {
	return s.interfaceAddrs
}

// SupportsIPv6 implements inet.Stack.SupportsIPv6.
func (s *Stack) SupportsIPv6() bool {
	return s.supportsIPv6
}

// TCPReceiveBufferSize implements inet.Stack.TCPReceiveBufferSize.
func (s *Stack) TCPReceiveBufferSize() (inet.TCPBufferSize, error) {
	return s.tcpRecvBufSize, nil
}

// SetTCPReceiveBufferSize implements inet.Stack.SetTCPReceiveBufferSize.
func (s *Stack) SetTCPReceiveBufferSize(size inet.TCPBufferSize) error {
	return syserror.EACCES
}

// TCPSendBufferSize implements inet.Stack.TCPSendBufferSize.
func (s *Stack) TCPSendBufferSize() (inet.TCPBufferSize, error) {
	return s.tcpSendBufSize, nil
}

// SetTCPSendBufferSize implements inet.Stack.SetTCPSendBufferSize.
func (s *Stack) SetTCPSendBufferSize(size inet.TCPBufferSize) error {
	return syserror.EACCES
}

// TCPSACKEnabled implements inet.Stack.TCPSACKEnabled.
func (s *Stack) TCPSACKEnabled() (bool, error) {
	return s.tcpSACKEnabled, nil
}

// SetTCPSACKEnabled implements inet.Stack.SetTCPSACKEnabled.
func (s *Stack) SetTCPSACKEnabled(enabled bool) error {
	return syserror.EACCES
}
