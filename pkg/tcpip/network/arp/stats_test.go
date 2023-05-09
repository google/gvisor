// Copyright 2021 The gVisor Authors.
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

package arp

import (
	"os"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/refs"
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
	if err := testutil.ValidateMultiCounterStats(reflect.ValueOf(&ep.stats.arp).Elem(), []reflect.Value{reflect.ValueOf(&refEP.ARP).Elem(), reflect.ValueOf(&refStack.ARP).Elem()}, testutil.ValidateMultiCounterStatsOptions{
		ExpectMultiCounterStat:            true,
		ExpectMultiIntegralStatCounterMap: false,
	}); err != nil {
		t.Error(err)
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
