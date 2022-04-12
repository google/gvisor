// Copyright 2022 The gVisor Authors.
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

package multicast

import (
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/refsvfs2"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/buffer"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

const (
	defaultMinTTL             = 10
	inputNICID    tcpip.NICID = 1
	outgoingNICID tcpip.NICID = 2
)

var (
	defaultAddress            = testutil.MustParse4("192.168.1.1")
	defaultRouteKey           = RouteKey{UnicastSource: defaultAddress, MulticastDestination: defaultAddress}
	defaultOutgoingInterfaces = []OutgoingInterface{{ID: outgoingNICID, MinTTL: defaultMinTTL}}
)

func newPacketBuffer(body string) stack.PacketBufferPtr {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Data: buffer.View(body).ToVectorisedView(),
	})
}

type configOption func(*Config)

func withMaxPendingQueueSize(size uint8) configOption {
	return func(c *Config) {
		c.MaxPendingQueueSize = size
	}
}

func withClock(clock tcpip.Clock) configOption {
	return func(c *Config) {
		c.Clock = clock
	}
}

func defaultConfig(opts ...configOption) Config {
	c := &Config{
		MaxPendingQueueSize: DefaultMaxPendingQueueSize,
		Clock:               faketime.NewManualClock(),
	}

	for _, opt := range opts {
		opt(c)
	}

	return *c
}

func TestInit(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		invokeTwice bool
		wantErr     error
	}{
		{
			name:        "MissingClock",
			config:      defaultConfig(withClock(nil)),
			invokeTwice: false,
			wantErr:     ErrMissingClock,
		},
		{
			name:        "AlreadyInitialized",
			config:      defaultConfig(),
			invokeTwice: true,
			wantErr:     ErrAlreadyInitialized,
		},
		{
			name:        "ValidConfig",
			config:      defaultConfig(),
			invokeTwice: false,
			wantErr:     nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			table := RouteTable{}
			err := table.Init(tc.config)

			if tc.invokeTwice {
				err = table.Init(tc.config)
			}

			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Errorf("got table.Init(%#v) = %s, want %s", tc.config, err, tc.wantErr)
			}
		})
	}
}

func TestNewInstalledRoute(t *testing.T) {
	table := RouteTable{}
	clock := faketime.NewManualClock()
	clock.Advance(5 * time.Second)

	config := defaultConfig(withClock(clock))
	if err := table.Init(config); err != nil {
		t.Fatalf("table.Init(%#v): %s", config, err)
	}

	route := table.NewInstalledRoute(inputNICID, defaultOutgoingInterfaces)
	expectedRoute := &InstalledRoute{expectedInputInterface: inputNICID, outgoingInterfaces: defaultOutgoingInterfaces, lastUsedTimestamp: atomicbitops.FromInt64(clock.Now().UnixMicro())}

	if diff := cmp.Diff(expectedRoute, route, cmp.Comparer(func(a *InstalledRoute, b *InstalledRoute) bool {
		if !cmp.Equal(a.OutgoingInterfaces(), b.OutgoingInterfaces()) {
			return false
		}

		if a.ExpectedInputInterface() != b.ExpectedInputInterface() {
			return false
		}

		return a.LastUsedTimestamp() == b.LastUsedTimestamp()
	})); diff != "" {
		t.Errorf("installed route mismatch (-want +got):\n%s", diff)
	}
}

func TestPendingRouteStates(t *testing.T) {
	table := RouteTable{}
	config := defaultConfig(withMaxPendingQueueSize(2))
	if err := table.Init(config); err != nil {
		t.Fatalf("table.Init(%#v): %s", config, err)
	}

	pkt := newPacketBuffer("hello")
	defer pkt.DecRef()
	// Queue two pending packets for the same route. The PendingRouteState should
	// transition from PendingRouteStateInstalled to PendingRouteStateAppended.
	for _, wantPendingRouteState := range [...]PendingRouteState{PendingRouteStateInstalled, PendingRouteStateAppended} {
		routeResult, err := table.GetRouteOrInsertPending(defaultRouteKey, pkt)

		if err != nil {
			t.Errorf("got table.GetRouteOrInsertPending(%#v, %#v) = (_, %v), want = (_, nil)", defaultRouteKey, pkt, err)
		}

		expectedResult := GetRouteResult{PendingRouteState: wantPendingRouteState}
		if diff := cmp.Diff(expectedResult, routeResult); diff != "" {
			t.Errorf("table.GetRouteOrInsertPending(%#v, %#v) GetRouteResult mismatch (-want +got):\n%s", defaultRouteKey, pkt, diff)
		}
	}

	// Queuing a third packet should yield an error since the pending queue is
	// already at max capacity.
	if _, err := table.GetRouteOrInsertPending(defaultRouteKey, pkt); err != ErrNoBufferSpace {
		t.Errorf("got table.GetRouteOrInsertPending(%#v, %#v) = (_, %v), want = (_, ErrNoBufferSpace)", defaultRouteKey, pkt, err)
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refsvfs2.DoLeakCheck()
	os.Exit(code)
}
