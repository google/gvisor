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

package rpcinet

import (
	"fmt"
	"strings"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/inet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/hostinet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet/conn"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet/notifier"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
	"gvisor.googlesource.com/gvisor/pkg/unet"
)

// Stack implements inet.Stack for RPC backed sockets.
type Stack struct {
	// We intentionally do not allow these values to be changed to remain
	// consistent with the other networking stacks.
	interfaces     map[int32]inet.Interface
	interfaceAddrs map[int32][]inet.InterfaceAddr
	supportsIPv6   bool
	tcpRecvBufSize inet.TCPBufferSize
	tcpSendBufSize inet.TCPBufferSize
	tcpSACKEnabled bool
	rpcConn        *conn.RPCConnection
	notifier       *notifier.Notifier
}

func readTCPBufferSizeFile(conn *conn.RPCConnection, filename string) (inet.TCPBufferSize, error) {
	contents, se := conn.RPCReadFile(filename)
	if se != nil {
		return inet.TCPBufferSize{}, fmt.Errorf("failed to read %s: %v", filename, se)
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

// NewStack returns a Stack containing the current state of the host network
// stack.
func NewStack(fd int32) (*Stack, error) {
	sock, err := unet.NewSocket(int(fd))
	if err != nil {
		return nil, err
	}

	stack := &Stack{
		interfaces:     make(map[int32]inet.Interface),
		interfaceAddrs: make(map[int32][]inet.InterfaceAddr),
		rpcConn:        conn.NewRPCConnection(sock),
	}

	var e error
	stack.notifier, e = notifier.NewRPCNotifier(stack.rpcConn)
	if e != nil {
		return nil, e
	}

	// Load the configuration values from procfs.
	tcpRMem, e := readTCPBufferSizeFile(stack.rpcConn, "/proc/sys/net/ipv4/tcp_rmem")
	if e != nil {
		return nil, e
	}
	stack.tcpRecvBufSize = tcpRMem

	tcpWMem, e := readTCPBufferSizeFile(stack.rpcConn, "/proc/sys/net/ipv4/tcp_wmem")
	if e != nil {
		return nil, e
	}
	stack.tcpSendBufSize = tcpWMem

	ipv6, se := stack.rpcConn.RPCReadFile("/proc/net/if_inet6")
	if len(string(ipv6)) > 0 {
		stack.supportsIPv6 = true
	}

	sackFile := "/proc/sys/net/ipv4/tcp_sack"
	sack, se := stack.rpcConn.RPCReadFile(sackFile)
	if se != nil {
		return nil, fmt.Errorf("failed to read %s: %v", sackFile, se)
	}
	stack.tcpSACKEnabled = strings.TrimSpace(string(sack)) != "0"

	links, err := stack.DoNetlinkRouteRequest(syscall.RTM_GETLINK)
	if err != nil {
		return nil, fmt.Errorf("RTM_GETLINK failed: %v", err)
	}

	addrs, err := stack.DoNetlinkRouteRequest(syscall.RTM_GETADDR)
	if err != nil {
		return nil, fmt.Errorf("RTM_GETADDR failed: %v", err)
	}

	e = hostinet.ExtractHostInterfaces(links, addrs, stack.interfaces, stack.interfaceAddrs)
	if e != nil {
		return nil, e
	}

	return stack, nil
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
	// To keep all the supported stacks consistent we don't allow changing this
	// value even though it would be possible via an RPC.
	return syserror.EACCES
}

// TCPSendBufferSize implements inet.Stack.TCPSendBufferSize.
func (s *Stack) TCPSendBufferSize() (inet.TCPBufferSize, error) {
	return s.tcpSendBufSize, nil
}

// SetTCPSendBufferSize implements inet.Stack.SetTCPSendBufferSize.
func (s *Stack) SetTCPSendBufferSize(size inet.TCPBufferSize) error {
	// To keep all the supported stacks consistent we don't allow changing this
	// value even though it would be possible via an RPC.
	return syserror.EACCES
}

// TCPSACKEnabled implements inet.Stack.TCPSACKEnabled.
func (s *Stack) TCPSACKEnabled() (bool, error) {
	return s.tcpSACKEnabled, nil
}

// SetTCPSACKEnabled implements inet.Stack.SetTCPSACKEnabled.
func (s *Stack) SetTCPSACKEnabled(enabled bool) error {
	// To keep all the supported stacks consistent we don't allow changing this
	// value even though it would be possible via an RPC.
	return syserror.EACCES
}
