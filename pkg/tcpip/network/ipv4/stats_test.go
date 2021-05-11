// Copyright 2020 The gVisor Authors.
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

package ipv4

import (
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

var _ stack.NetworkInterface = (*testInterface)(nil)

type testInterface struct {
	stack.NetworkInterface
	nicID tcpip.NICID
}

func (t *testInterface) ID() tcpip.NICID {
	return t.nicID
}

func knownNICIDs(proto *protocol) []tcpip.NICID {
	var nicIDs []tcpip.NICID

	for k := range proto.mu.eps {
		nicIDs = append(nicIDs, k)
	}

	return nicIDs
}

func TestClearEndpointFromProtocolOnClose(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocol},
	})
	proto := s.NetworkProtocolInstance(ProtocolNumber).(*protocol)
	nic := testInterface{nicID: 1}
	ep := proto.NewEndpoint(&nic, nil).(*endpoint)
	var nicIDs []tcpip.NICID

	proto.mu.Lock()
	foundEP, hasEndpointBeforeClose := proto.mu.eps[nic.ID()]
	nicIDs = knownNICIDs(proto)
	proto.mu.Unlock()

	if !hasEndpointBeforeClose {
		t.Fatalf("expected to find the nic id %d in the protocol's endpoint map (%v)", nic.ID(), nicIDs)
	}
	if foundEP != ep {
		t.Fatalf("found an incorrect endpoint mapped to nic id %d", nic.ID())
	}

	ep.Close()

	proto.mu.Lock()
	_, hasEP := proto.mu.eps[nic.ID()]
	nicIDs = knownNICIDs(proto)
	proto.mu.Unlock()
	if hasEP {
		t.Fatalf("unexpectedly found an endpoint mapped to the nic id %d in the protocol's known nic ids (%v)", nic.ID(), nicIDs)
	}
}

func TestMultiCounterStatsInitialization(t *testing.T) {
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{NewProtocol},
	})
	proto := s.NetworkProtocolInstance(ProtocolNumber).(*protocol)
	var nic testInterface
	ep := proto.NewEndpoint(&nic, nil).(*endpoint)
	// At this point, the Stack's stats and the NetworkEndpoint's stats are
	// expected to be bound by a MultiCounterStat.
	refStack := s.Stats()
	refEP := ep.stats.localStats
	if err := testutil.ValidateMultiCounterStats(reflect.ValueOf(&ep.stats.ip).Elem(), []reflect.Value{reflect.ValueOf(&refEP.IP).Elem(), reflect.ValueOf(&refStack.IP).Elem()}); err != nil {
		t.Error(err)
	}
	if err := testutil.ValidateMultiCounterStats(reflect.ValueOf(&ep.stats.icmp).Elem(), []reflect.Value{reflect.ValueOf(&refEP.ICMP).Elem(), reflect.ValueOf(&refStack.ICMP.V4).Elem()}); err != nil {
		t.Error(err)
	}
	if err := testutil.ValidateMultiCounterStats(reflect.ValueOf(&ep.stats.igmp).Elem(), []reflect.Value{reflect.ValueOf(&refEP.IGMP).Elem(), reflect.ValueOf(&refStack.IGMP).Elem()}); err != nil {
		t.Error(err)
	}
}
