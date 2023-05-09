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
	"gvisor.dev/gvisor/pkg/bufferv2"
	"gvisor.dev/gvisor/pkg/refs"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/testutil"
)

const (
	defaultMinTTL             = 10
	defaultMTU                = 1500
	inputNICID    tcpip.NICID = 1
	outgoingNICID tcpip.NICID = 2
	defaultNICID  tcpip.NICID = 3
)

var (
	defaultAddress            = testutil.MustParse4("192.168.1.1")
	defaultRouteKey           = stack.UnicastSourceAndMulticastDestination{Source: defaultAddress, Destination: defaultAddress}
	defaultOutgoingInterfaces = []stack.MulticastRouteOutgoingInterface{{ID: outgoingNICID, MinTTL: defaultMinTTL}}
	defaultRoute              = stack.MulticastRoute{inputNICID, defaultOutgoingInterfaces}
)

func newPacketBuffer(body string) stack.PacketBufferPtr {
	return stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: bufferv2.MakeWithData([]byte(body)),
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
	if !cmp.Equal(a.OutgoingInterfaces, b.OutgoingInterfaces) {
		return false
	}

	if a.ExpectedInputInterface != b.ExpectedInputInterface {
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
			defer table.Close()
			err := table.Init(tc.config)

			if tc.invokeTwice {
				err = table.Init(tc.config)
			}

			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Errorf("table.Init(%#v) = %s, want %s", tc.config, err, tc.wantErr)
			}
		})
	}
}

func TestNewInstalledRoute(t *testing.T) {
	table := RouteTable{}
	defer table.Close()
	clock := faketime.NewManualClock()
	clock.Advance(5 * time.Second)

	config := defaultConfig(withClock(clock))
	if err := table.Init(config); err != nil {
		t.Fatalf("table.Init(%#v): %s", config, err)
	}

	route := table.NewInstalledRoute(defaultRoute)

	expectedRoute := &InstalledRoute{
		MulticastRoute:    defaultRoute,
		lastUsedTimestamp: clock.NowMonotonic(),
	}

	if diff := cmp.Diff(expectedRoute, route, cmp.Comparer(installedRouteComparer)); diff != "" {
		t.Errorf("Installed route mismatch (-want +got):\n%s", diff)
	}
}

func TestGetRouteResultStates(t *testing.T) {
	table := RouteTable{}
	defer table.Close()
	config := defaultConfig(withMaxPendingQueueSize(2))
	if err := table.Init(config); err != nil {
		t.Fatalf("table.Init(%#v): %s", config, err)
	}

	pkt := newPacketBuffer("hello")
	defer pkt.DecRef()
	// Queue two pending packets for the same route. The GetRouteResultState
	// should transition from NoRouteFoundAndPendingInserted to
	// PacketQueuedInPendingRoute.
	for _, wantPendingRouteState := range []GetRouteResultState{NoRouteFoundAndPendingInserted, PacketQueuedInPendingRoute} {
		routeResult, hasBufferSpace := table.GetRouteOrInsertPending(defaultRouteKey, pkt)

		if !hasBufferSpace {
			t.Errorf("table.GetRouteOrInsertPending(%#v, %#v) = (_, false), want = (_, true)", defaultRouteKey, pkt)
		}

		expectedResult := GetRouteResult{GetRouteResultState: wantPendingRouteState}
		if diff := cmp.Diff(expectedResult, routeResult); diff != "" {
			t.Errorf("table.GetRouteOrInsertPending(%#v, %#v) GetRouteResult mismatch (-want +got):\n%s", defaultRouteKey, pkt, diff)
		}
	}

	// Queuing a third packet should yield an error since the pending queue is
	// already at max capacity.
	if _, hasBufferSpace := table.GetRouteOrInsertPending(defaultRouteKey, pkt); hasBufferSpace {
		t.Errorf("table.GetRouteOrInsertPending(%#v, %#v) = (_, true), want = (_, false)", defaultRouteKey, pkt)
	}
}

func TestPendingRouteExpiration(t *testing.T) {
	pkt := newPacketBuffer("foo")
	defer pkt.DecRef()

	testCases := []struct {
		name                string
		advanceBeforeInsert time.Duration
		advanceAfterInsert  time.Duration
		wantPendingRoute    bool
	}{
		{
			name:                "not expired",
			advanceBeforeInsert: DefaultCleanupInterval / 2,
			// The time is advanced far enough to run the cleanup routine, but not
			// far enough to expire the route.
			advanceAfterInsert: DefaultCleanupInterval,
			wantPendingRoute:   true,
		},
		{
			name: "expired",
			// The cleanup routine will be run twice. The second invocation will
			// remove the expired route.
			advanceBeforeInsert: DefaultCleanupInterval / 2,
			advanceAfterInsert:  DefaultCleanupInterval * 2,
			wantPendingRoute:    false,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()

			table := RouteTable{}
			defer table.Close()
			config := defaultConfig(withClock(clock))

			if err := table.Init(config); err != nil {
				t.Fatalf("table.Init(%#v): %s", config, err)
			}

			clock.Advance(test.advanceBeforeInsert)

			if _, hasBufferSpace := table.GetRouteOrInsertPending(defaultRouteKey, pkt); !hasBufferSpace {
				t.Fatalf("table.GetRouteOrInsertPending(%#v, %#v): false", defaultRouteKey, pkt)
			}

			clock.Advance(test.advanceAfterInsert)

			table.pendingMu.RLock()
			_, ok := table.pendingRoutes[defaultRouteKey]

			if table.isCleanupRoutineRunning != test.wantPendingRoute {
				t.Errorf("table.isCleanupRoutineRunning = %t, want = %t", table.isCleanupRoutineRunning, test.wantPendingRoute)
			}
			table.pendingMu.RUnlock()

			if test.wantPendingRoute != ok {
				t.Errorf("table.pendingRoutes[%#v] = (_, %t), want = (_, %t)", defaultRouteKey, ok, test.wantPendingRoute)
			}
		})
	}
}

func TestAddInstalledRouteWithPending(t *testing.T) {
	pkt := newPacketBuffer("foo")
	defer pkt.DecRef()

	cmpOpts := []cmp.Option{
		cmp.Transformer("AsSlices", func(pkt stack.PacketBufferPtr) [][]byte {
			return pkt.AsSlices()
		}),
		cmp.Comparer(func(a [][]byte, b [][]byte) bool {
			return cmp.Equal(a, b)
		}),
	}

	testCases := []struct {
		name    string
		advance time.Duration
		want    []stack.PacketBufferPtr
	}{
		{
			name:    "not expired",
			advance: DefaultPendingRouteExpiration,
			want:    []stack.PacketBufferPtr{pkt},
		},
		{
			name:    "expired",
			advance: DefaultPendingRouteExpiration + 1,
			want:    nil,
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			clock := faketime.NewManualClock()

			table := RouteTable{}
			defer table.Close()
			config := defaultConfig(withClock(clock))

			if err := table.Init(config); err != nil {
				t.Fatalf("table.Init(%#v): %s", config, err)
			}

			if _, hasBufferSpace := table.GetRouteOrInsertPending(defaultRouteKey, pkt); !hasBufferSpace {
				t.Fatalf("table.GetRouteOrInsertPending(%#v, %#v): false", defaultRouteKey, pkt)
			}

			// Disable the cleanup routine.
			table.cleanupPendingRoutesTimer.Stop()

			clock.Advance(test.advance)

			route := table.NewInstalledRoute(defaultRoute)
			pendingPackets := table.AddInstalledRoute(defaultRouteKey, route)

			if diff := cmp.Diff(test.want, pendingPackets, cmpOpts...); diff != "" {
				t.Errorf("table.AddInstalledRoute(%#v, %#v) mismatch (-want +got):\n%s", defaultRouteKey, route, diff)
			}

			for _, pendingPkt := range pendingPackets {
				pendingPkt.DecRef()
			}

			// Verify that the pending route is actually deleted.
			table.pendingMu.RLock()
			if pendingRoute, ok := table.pendingRoutes[defaultRouteKey]; ok {
				t.Errorf("table.pendingRoutes[%#v] = (%#v, true), want (_, false)", defaultRouteKey, pendingRoute)
			}
			table.pendingMu.RUnlock()
		})
	}
}

func TestAddInstalledRouteWithNoPending(t *testing.T) {
	table := RouteTable{}
	defer table.Close()
	config := defaultConfig()
	if err := table.Init(config); err != nil {
		t.Fatalf("table.Init(%#v): %s", config, err)
	}

	firstRoute := table.NewInstalledRoute(defaultRoute)

	secondMulticastRoute := stack.MulticastRoute{defaultNICID, defaultOutgoingInterfaces}
	secondRoute := table.NewInstalledRoute(secondMulticastRoute)

	pkt := newPacketBuffer("hello")
	defer pkt.DecRef()
	for _, route := range [...]*InstalledRoute{firstRoute, secondRoute} {
		if pendingPackets := table.AddInstalledRoute(defaultRouteKey, route); pendingPackets != nil {
			t.Errorf("table.AddInstalledRoute(%#v, %#v) = %#v, want = false", defaultRouteKey, route, pendingPackets)
		}

		// AddInstalledRoute is invoked for the same routeKey two times. Verify
		// that the fetched InstalledRoute reflects the most recent invocation of
		// AddInstalledRoute.
		routeResult, hasBufferSpace := table.GetRouteOrInsertPending(defaultRouteKey, pkt)

		if !hasBufferSpace {
			t.Fatalf("table.GetRouteOrInsertPending(%#v, %#v): false", defaultRouteKey, pkt)
		}

		if routeResult.GetRouteResultState != InstalledRouteFound {
			t.Errorf("routeResult.GetRouteResultState = %s, want = InstalledRouteFound", routeResult.GetRouteResultState)
		}

		if diff := cmp.Diff(route, routeResult.InstalledRoute, cmp.Comparer(installedRouteComparer)); diff != "" {
			t.Errorf("route.InstalledRoute mismatch (-want +got):\n%s", diff)
		}
	}
}

func TestRemoveInstalledRoute(t *testing.T) {
	table := RouteTable{}
	defer table.Close()
	config := defaultConfig()
	if err := table.Init(config); err != nil {
		t.Fatalf("table.Init(%#v): %s", config, err)
	}

	route := table.NewInstalledRoute(defaultRoute)

	table.AddInstalledRoute(defaultRouteKey, route)

	if removed := table.RemoveInstalledRoute(defaultRouteKey); !removed {
		t.Errorf("table.RemoveInstalledRoute(%#v) = false, want = true", defaultRouteKey)
	}

	pkt := newPacketBuffer("hello")
	defer pkt.DecRef()

	result, hasBufferSpace := table.GetRouteOrInsertPending(defaultRouteKey, pkt)

	if !hasBufferSpace {
		t.Fatalf("table.GetRouteOrInsertPending(%#v, %#v): false", defaultRouteKey, pkt)
	}

	if result.InstalledRoute != nil {
		t.Errorf("result.InstalledRoute = %v, want = nil", result.InstalledRoute)
	}
}

func TestRemoveInstalledRouteWithNoMatchingRoute(t *testing.T) {
	table := RouteTable{}
	defer table.Close()
	config := defaultConfig()
	if err := table.Init(config); err != nil {
		t.Fatalf("table.Init(%#v): %s", config, err)
	}

	if removed := table.RemoveInstalledRoute(defaultRouteKey); removed {
		t.Errorf("table.RemoveInstalledRoute(%#v) = true, want = false", defaultRouteKey)
	}
}

func TestRemoveAllInstalledRoutes(t *testing.T) {
	otherAddress := testutil.MustParse4("192.168.2.1")

	table := RouteTable{}
	defer table.Close()
	config := defaultConfig()
	if err := table.Init(config); err != nil {
		t.Fatalf("table.Init(%#v): %s", config, err)
	}

	routes := map[stack.UnicastSourceAndMulticastDestination]stack.MulticastRoute{
		defaultRouteKey: defaultRoute,
		stack.UnicastSourceAndMulticastDestination{otherAddress, otherAddress}: defaultRoute,
	}

	for key, route := range routes {
		installedRoute := table.NewInstalledRoute(route)
		table.AddInstalledRoute(key, installedRoute)
	}

	table.RemoveAllInstalledRoutes()

	for key := range routes {
		pkt := newPacketBuffer("hello")
		defer pkt.DecRef()

		result, hasBufferSpace := table.GetRouteOrInsertPending(key, pkt)

		if !hasBufferSpace {
			t.Fatalf("table.GetRouteOrInsertPending(%#v, %#v): false", key, pkt)
		}

		if result.InstalledRoute != nil {
			t.Errorf("result.InstalledRoute = %v, want = nil", result.InstalledRoute)
		}
	}
}

func TestGetLastUsedTimestampWithNoMatchingRoute(t *testing.T) {
	table := RouteTable{}
	defer table.Close()
	config := defaultConfig()
	if err := table.Init(config); err != nil {
		t.Fatalf("table.Init(%#v): %s", config, err)
	}

	if _, found := table.GetLastUsedTimestamp(defaultRouteKey); found {
		t.Errorf("table.GetLastUsedTimetsamp(%#v) = (_, true), want = (_, false)", defaultRouteKey)
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
			defer table.Close()
			config := defaultConfig(withClock(clock))
			if err := table.Init(config); err != nil {
				t.Fatalf("table.Init(%#v): %s", config, err)
			}

			route := table.NewInstalledRoute(defaultRoute)

			table.AddInstalledRoute(defaultRouteKey, route)

			route.SetLastUsedTimestamp(test.lastUsedTime)

			// Verify that the updated timestamp is actually reflected in the RouteTable.
			timestamp, found := table.GetLastUsedTimestamp(defaultRouteKey)

			if !found {
				t.Fatalf("table.GetLastUsedTimestamp(%#v) = (_, false_), want = (_, true)", defaultRouteKey)
			}

			if timestamp != test.wantLastUsedTime {
				t.Errorf("table.GetLastUsedTimestamp(%#v) = (%s, _), want = (%s, _)", defaultRouteKey, timestamp, test.wantLastUsedTime)
			}
		})
	}
}

func TestMain(m *testing.M) {
	refs.SetLeakMode(refs.LeaksPanic)
	code := m.Run()
	refs.DoLeakCheck()
	os.Exit(code)
}
