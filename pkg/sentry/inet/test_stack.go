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

package inet

import "gvisor.dev/gvisor/pkg/tcpip/stack"

// TestStack is a dummy implementation of Stack for tests.
type TestStack struct {
	InterfacesMap     map[int32]Interface
	InterfaceAddrsMap map[int32][]InterfaceAddr
	RouteList         []Route
	SupportsIPv6Flag  bool
	TCPRecvBufSize    TCPBufferSize
	TCPSendBufSize    TCPBufferSize
	TCPSACKFlag       bool
}

// NewTestStack returns a TestStack with no network interfaces. The value of
// all other options is unspecified; tests that rely on specific values must
// set them explicitly.
func NewTestStack() *TestStack {
	return &TestStack{
		InterfacesMap:     make(map[int32]Interface),
		InterfaceAddrsMap: make(map[int32][]InterfaceAddr),
	}
}

// Interfaces implements Stack.Interfaces.
func (s *TestStack) Interfaces() map[int32]Interface {
	return s.InterfacesMap
}

// InterfaceAddrs implements Stack.InterfaceAddrs.
func (s *TestStack) InterfaceAddrs() map[int32][]InterfaceAddr {
	return s.InterfaceAddrsMap
}

// SupportsIPv6 implements Stack.SupportsIPv6.
func (s *TestStack) SupportsIPv6() bool {
	return s.SupportsIPv6Flag
}

// TCPReceiveBufferSize implements Stack.TCPReceiveBufferSize.
func (s *TestStack) TCPReceiveBufferSize() (TCPBufferSize, error) {
	return s.TCPRecvBufSize, nil
}

// SetTCPReceiveBufferSize implements Stack.SetTCPReceiveBufferSize.
func (s *TestStack) SetTCPReceiveBufferSize(size TCPBufferSize) error {
	s.TCPRecvBufSize = size
	return nil
}

// TCPSendBufferSize implements Stack.TCPSendBufferSize.
func (s *TestStack) TCPSendBufferSize() (TCPBufferSize, error) {
	return s.TCPSendBufSize, nil
}

// SetTCPSendBufferSize implements Stack.SetTCPSendBufferSize.
func (s *TestStack) SetTCPSendBufferSize(size TCPBufferSize) error {
	s.TCPSendBufSize = size
	return nil
}

// TCPSACKEnabled implements Stack.TCPSACKEnabled.
func (s *TestStack) TCPSACKEnabled() (bool, error) {
	return s.TCPSACKFlag, nil
}

// SetTCPSACKEnabled implements Stack.SetTCPSACKEnabled.
func (s *TestStack) SetTCPSACKEnabled(enabled bool) error {
	s.TCPSACKFlag = enabled
	return nil
}

// Statistics implements inet.Stack.Statistics.
func (s *TestStack) Statistics(stat interface{}, arg string) error {
	return nil
}

// RouteTable implements Stack.RouteTable.
func (s *TestStack) RouteTable() []Route {
	return s.RouteList
}

// Resume implements Stack.Resume.
func (s *TestStack) Resume() {}

// RegisteredEndpoints implements inet.Stack.RegisteredEndpoints.
func (s *TestStack) RegisteredEndpoints() []stack.TransportEndpoint {
	return nil
}

// CleanupEndpoints implements inet.Stack.CleanupEndpoints.
func (s *TestStack) CleanupEndpoints() []stack.TransportEndpoint {
	return nil
}

// RestoreCleanupEndpoints implements inet.Stack.RestoreCleanupEndpoints.
func (s *TestStack) RestoreCleanupEndpoints([]stack.TransportEndpoint) {}
