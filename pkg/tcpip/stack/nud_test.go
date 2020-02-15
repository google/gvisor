// Copyright 2019 The gVisor Authors.
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

package stack_test

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TestSetNUDConfigurationFailsForBadNICID tests to make sure we get an error if
// we attempt to update NUD configurations using an invalid NICID.
func TestSetNUDConfigurationFailsForBadNICID(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
	})

	// No NIC with ID 1 yet.
	if got := s.SetNUDConfigurations(1, stack.NUDConfigurations{}); got != tcpip.ErrUnknownNICID {
		t.Fatalf("got s.SetNDPConfigurations = %v, want = %s", got, tcpip.ErrUnknownNICID)
	}
}
