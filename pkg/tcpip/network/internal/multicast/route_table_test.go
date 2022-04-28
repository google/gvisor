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
	defaultNICID  tcpip.NICID = 3
)

var (
	defaultAddress            = testutil.MustParse4("192.168.1.1")
	defaultRouteKey           = RouteKey{UnicastSource: defaultAddress, MulticastDestination: defaultAddress}
	defaultOutgoingInterfaces = []OutgoingInterface{{ID: outgoingNICID, MinTTL: defaultMinTTL}}
)

func newPacketBuffer(body string) *stack.PacketBuffer {
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

func installedRouteComparer(a *InstalledRoute, b *InstalledRoute) bool {
	if !cmp.Equal(a.OutgoingInterfaces(), b.OutgoingInterfaces()) {
		return false
	}

	if a.ExpectedInputInterface() != b.ExpectedInputInterface() {
		return false
	}

	return a.LastUsedTimestamp() == b.LastUsedTimestamp()
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
	expectedRoute := &InstalledRoute{expectedInputInterface: inputNICID, outgoingInterfaces: defaultOutgoingInterfaces, lastUsedTimestamp: clock.NowMonotonic()}

	if diff := cmp.Diff(expectedRoute, route, cmp.Comparer(installedRouteComparer)); diff != "" {
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
	for _, wantPendingRouteState := range []PendingRouteState{PendingRouteStateInstalled, PendingRouteStateAppended} {
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

func TestAddInstalledRouteWithPending(t *testing.T) {
	table := RouteTable{}
	config := defaultConfig()
	if err := table.Init(config); err != nil {
		t.Fatalf("table.Init(%#v): %s", config, err)
	}

	wantPkt := newPacketBuffer("hello")
	defer wantPkt.DecRef()
	// Queue a pending packet. This packet should later be returned in a
	// PendingRoute when table.AddInstalledRoute is invoked.
	_, err := table.GetRouteOrInsertPending(defaultRouteKey, wantPkt)

	if err != nil {
		t.Fatalf("table.GetRouteOrInsertPending(%#v, %#v): %v", defaultRouteKey, wantPkt, err)
	}

	route := table.NewInstalledRoute(inputNICID, defaultOutgoingInterfaces)

	pendingRoute, wasPending := table.AddInstalledRoute(defaultRouteKey, route)
	if !wasPending {
		t.Fatalf("got table.AddInstalledRoute(%#v, %#v) = (nil, false), want = (_, true)", defaultRouteKey, route)
	}

	// Verify that packets are properly dequeued from the PendingRoute.
	pkt, err := pendingRoute.Dequeue()

	if err != nil {
		t.Fatalf("got pendingRoute.Dequeue() = (_, %v), want = (_, nil)", err)
	}

	if !cmp.Equal(wantPkt.Views(), pkt.Views()) {
		t.Errorf("got pendingRoute.Dequeue() = (%v, nil), want = (%v, nil)", pkt.Views(), wantPkt.Views())
	}

	if !pendingRoute.IsEmpty() {
		t.Errorf("got pendingRoute.IsEmpty() = false, want = true")
	}

	// Verify that the pending route is deleted (not returned on subsequent
	// calls to AddInstalledRoute).
	pendingRoute, wasPending = table.AddInstalledRoute(defaultRouteKey, route)
	if wasPending {
		t.Errorf("got table.AddInstalledRoute(%#v, %#v) = (%#v, true), want (_, false)", defaultRouteKey, route, pendingRoute)
	}
}

func TestAddInstalledRouteWithNoPending(t *testing.T) {
	table := RouteTable{}
	config := defaultConfig()
	if err := table.Init(config); err != nil {
		t.Fatalf("table.Init(%#v): %s", config, err)
	}

	firstRoute := table.NewInstalledRoute(inputNICID, defaultOutgoingInterfaces)
	secondRoute := table.NewInstalledRoute(defaultNICID, defaultOutgoingInterfaces)

	pkt := newPacketBuffer("hello")
	defer pkt.DecRef()
	for _, route := range [...]*InstalledRoute{firstRoute, secondRoute} {
		if pendingRoute, wasPending := table.AddInstalledRoute(defaultRouteKey, route); wasPending {
			t.Errorf("got table.AddInstalledRoute(%#v, %#v) = (%#v, true), want = (_, false)", defaultRouteKey, route, pendingRoute)
		}

		// AddInstalledRoute is invoked for the same routeKey two times. Verify
		// that the fetched InstalledRoute reflects the most recent invocation of
		// AddInstalledRoute.
		routeResult, err := table.GetRouteOrInsertPending(defaultRouteKey, pkt)

		if err != nil {
			t.Fatalf("table.GetRouteOrInsertPending(%#v, %#v): %v", defaultRouteKey, pkt, err)
		}

		if routeResult.PendingRouteState != PendingRouteStateNone {
			t.Errorf("got routeResult.PendingRouteState = %s, want = PendingRouteStateNone", routeResult.PendingRouteState)
		}

		if diff := cmp.Diff(route, routeResult.InstalledRoute, cmp.Comparer(installedRouteComparer)); diff != "" {
			t.Errorf("route.InstalledRoute mismatch (-want +got):\n%s", diff)
		}
	}
}

func TestRemoveInstalledRoute(t *testing.T) {
	table := RouteTable{}
	config := defaultConfig()
	if err := table.Init(config); err != nil {
		t.Fatalf("table.Init(%#v): %s", config, err)
	}

	route := table.NewInstalledRoute(inputNICID, defaultOutgoingInterfaces)

	table.AddInstalledRoute(defaultRouteKey, route)

	if removed := table.RemoveInstalledRoute(defaultRouteKey); !removed {
		t.Errorf("got table.RemoveInstalledRoute(%#v) = false, want = true", defaultRouteKey)
	}

	pkt := newPacketBuffer("hello")
	defer pkt.DecRef()

	result, err := table.GetRouteOrInsertPending(defaultRouteKey, pkt)

	if err != nil {
		t.Fatalf("table.GetRouteOrInsertPending(%#v, %#v): %v", defaultRouteKey, pkt, err)
	}

	if result.InstalledRoute != nil {
		t.Errorf("got result.InstalledRoute = %v, want = nil", result.InstalledRoute)
	}
}

func TestRemoveInstalledRouteWithNoMatchingRoute(t *testing.T) {
	table := RouteTable{}
	config := defaultConfig()
	if err := table.Init(config); err != nil {
		t.Fatalf("table.Init(%#v): %s", config, err)
	}

	if removed := table.RemoveInstalledRoute(defaultRouteKey); removed {
		t.Errorf("got table.RemoveInstalledRoute(%#v) = true, want = false", defaultRouteKey)
	}
}

func TestGetLastUsedTimestampWithNoMatchingRoute(t *testing.T) {
	table := RouteTable{}
	config := defaultConfig()
	if err := table.Init(config); err != nil {
		t.Fatalf("table.Init(%#v): %s", config, err)
	}

	if _, found := table.GetLastUsedTimestamp(defaultRouteKey); found {
		t.Errorf("got table.GetLastUsedTimetsamp(%#v) = (_, true), want = (_, false)", defaultRouteKey)
	}
}

func TestSetLastUsedTimestamp(t *testing.T) {
	clock := faketime.NewManualClock()
	clock.Advance(10 * time.Second)

	currentTime := clock.NowMonotonic()
	validLastUsedTime := currentTime.Add(10 * time.Second)

	tests := []struct {
		name             string
		lastUsedTime     tcpip.MonotonicTime
		wantLastUsedTime tcpip.MonotonicTime
	}{
		{
			name:             "valid timestamp",
			lastUsedTime:     validLastUsedTime,
			wantLastUsedTime: validLastUsedTime,
		},
		{
			name:             "timestamp before",
			lastUsedTime:     currentTime.Add(-5 * time.Second),
			wantLastUsedTime: currentTime,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			table := RouteTable{}
			config := defaultConfig(withClock(clock))
			if err := table.Init(config); err != nil {
				t.Fatalf("table.Init(%#v): %s", config, err)
			}

			route := table.NewInstalledRoute(inputNICID, defaultOutgoingInterfaces)

			table.AddInstalledRoute(defaultRouteKey, route)

			route.SetLastUsedTimestamp(test.lastUsedTime)

			// Verify that the updated timestamp is actually reflected in the RouteTable.
			timestamp, found := table.GetLastUsedTimestamp(defaultRouteKey)

			if !found {
				t.Fatalf("got table.GetLastUsedTimestamp(%#v) = (_, false_), want = (_, true)", defaultRouteKey)
			}

			if got, want := timestamp.Nanoseconds(), test.wantLastUsedTime.Nanoseconds(); got != want {
				t.Errorf("got table.GetLastUsedTimestamp(%#v) = (%v, _), want (%v, _)", defaultRouteKey, got, want)
			}
		})
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refsvfs2.DoLeakCheck()
	os.Exit(code)
}
