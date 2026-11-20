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

package stack

import (
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
)

// TestBridgeShouldLearnLocked checks the conditions that DeliverNetworkPacket
// checks again once it holds bridge.mu for writing, after the port or the
// bridge's addresses may have changed.
func TestBridgeShouldLearnLocked(t *testing.T) {
	const (
		remote    = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x01")
		multicast = tcpip.LinkAddress("\x01\x00\x5e\x00\x00\x01")
		portAddr  = tcpip.LinkAddress("\x02\x00\x00\x00\x00\x02")
	)
	b := NewBridgeEndpoint(1500)
	port := &bridgePort{bridge: b, nic: &nic{id: 1}}
	removed := &bridgePort{bridge: b, nic: &nic{id: 2}}

	b.mu.Lock()
	defer b.mu.Unlock()
	b.ports[port.nic.id] = port

	if !b.shouldLearnLocked(port, remote) {
		t.Errorf("shouldLearnLocked(port, %s) = false, want true", remote)
	}
	if b.shouldLearnLocked(removed, remote) {
		t.Errorf("shouldLearnLocked(removed port, %s) = true, want false", remote)
	}
	if b.shouldLearnLocked(port, multicast) {
		t.Errorf("shouldLearnLocked(port, %s) = true, want false for a multicast address", multicast)
	}
	if b.shouldLearnLocked(port, b.addr) {
		t.Errorf("shouldLearnLocked(port, %s) = true, want false for the bridge's address", b.addr)
	}
	b.localAddrs[portAddr]++
	if b.shouldLearnLocked(port, portAddr) {
		t.Errorf("shouldLearnLocked(port, %s) = true, want false for a port's address", portAddr)
	}
	b.addFDBEntryLocked(remote, port, 0)
	if b.shouldLearnLocked(port, remote) {
		t.Errorf("shouldLearnLocked(port, %s) = true, want false once learned", remote)
	}
}
