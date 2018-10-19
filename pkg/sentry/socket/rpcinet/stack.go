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

package rpcinet

import (
	"fmt"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/sentry/inet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/hostinet"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet/conn"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/rpcinet/notifier"
	"gvisor.googlesource.com/gvisor/pkg/syserr"
	"gvisor.googlesource.com/gvisor/pkg/unet"
)

// Stack implements inet.Stack for RPC backed sockets.
type Stack struct {
	interfaces     map[int32]inet.Interface
	interfaceAddrs map[int32][]inet.InterfaceAddr
	rpcConn        *conn.RPCConnection
	notifier       *notifier.Notifier
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

// RPCReadFile will execute the ReadFile helper RPC method which avoids the
// common pattern of open(2), read(2), close(2) by doing all three operations
// as a single RPC. It will read the entire file or return EFBIG if the file
// was too large.
func (s *Stack) RPCReadFile(path string) ([]byte, *syserr.Error) {
	return s.rpcConn.RPCReadFile(path)
}

// RPCWriteFile will execute the WriteFile helper RPC method which avoids the
// common pattern of open(2), write(2), write(2), close(2) by doing all
// operations as a single RPC.
func (s *Stack) RPCWriteFile(path string, data []byte) (int64, *syserr.Error) {
	return s.rpcConn.RPCWriteFile(path, data)
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
	panic("rpcinet handles procfs directly this method should not be called")
}

// TCPReceiveBufferSize implements inet.Stack.TCPReceiveBufferSize.
func (s *Stack) TCPReceiveBufferSize() (inet.TCPBufferSize, error) {
	panic("rpcinet handles procfs directly this method should not be called")
}

// SetTCPReceiveBufferSize implements inet.Stack.SetTCPReceiveBufferSize.
func (s *Stack) SetTCPReceiveBufferSize(size inet.TCPBufferSize) error {
	panic("rpcinet handles procfs directly this method should not be called")

}

// TCPSendBufferSize implements inet.Stack.TCPSendBufferSize.
func (s *Stack) TCPSendBufferSize() (inet.TCPBufferSize, error) {
	panic("rpcinet handles procfs directly this method should not be called")

}

// SetTCPSendBufferSize implements inet.Stack.SetTCPSendBufferSize.
func (s *Stack) SetTCPSendBufferSize(size inet.TCPBufferSize) error {
	panic("rpcinet handles procfs directly this method should not be called")
}

// TCPSACKEnabled implements inet.Stack.TCPSACKEnabled.
func (s *Stack) TCPSACKEnabled() (bool, error) {
	panic("rpcinet handles procfs directly this method should not be called")
}

// SetTCPSACKEnabled implements inet.Stack.SetTCPSACKEnabled.
func (s *Stack) SetTCPSACKEnabled(enabled bool) error {
	panic("rpcinet handles procfs directly this method should not be called")
}
