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

package stack_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/state"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

type ndpDispatcherContextKey struct{}

func (*ndpDispatcher) StateTypeName() string {
	return "gvisor.dev/gvisor/pkg/tcpip/stack_test.ndpDispatcher"
}

func (*ndpDispatcher) StateFields() []string { return nil }

func (*ndpDispatcher) StateSave(state.Sink) {}

func (n *ndpDispatcher) StateLoad(ctx context.Context, _ state.Source) {
	// Test observation channels belong to the test, not the saved network.
	*n = *ctx.Value(ndpDispatcherContextKey{}).(*ndpDispatcher)
}

func init() {
	state.Register((*ndpDispatcher)(nil))
}

func newNDPStackForRestore(t *testing.T, configs ipv6.NDPConfigurations) (*ndpDispatcher, *channel.Endpoint, *stack.Stack, *faketime.ManualClock) {
	t.Helper()
	disp := &ndpDispatcher{
		offLinkRouteC:   make(chan ndpOffLinkRouteEvent, 16),
		prefixC:         make(chan ndpPrefixEvent, 16),
		autoGenAddrC:    make(chan ndpAutoGenAddrEvent, 16),
		autoGenAddrNewC: make(chan ndpAutoGenAddrNewEvent, 16),
	}
	clock := faketime.NewManualClock()
	s := stack.New(stack.Options{
		NetworkProtocols: []stack.NetworkProtocolFactory{ipv6.NewProtocolWithOptions(ipv6.Options{
			NDPConfigs: configs,
			NDPDisp:    disp,
		})},
		Clock: clock,
	})
	t.Cleanup(s.Destroy)
	e := channel.New(0, 1280, linkAddr1)
	e.LinkEPCapabilities |= stack.CapabilitySaveRestore
	if err := s.CreateNICWithOptions(1, e, stack.NICOptions{Name: "ndp", Kind: "tun"}); err != nil {
		t.Fatalf("CreateNICWithOptions: %s", err)
	}
	return disp, e, s, clock
}

func restoreNDPStack(t *testing.T, s *stack.Stack, disp *ndpDispatcher, delay time.Duration) (*stack.Stack, *faketime.ManualClock) {
	t.Helper()
	var buf bytes.Buffer
	if _, err := state.Save(context.Background(), &buf, s); err != nil {
		t.Fatalf("Save: %s", err)
	}
	restored := stack.New(stack.Options{})
	t.Cleanup(restored.Destroy)
	ctx := context.WithValue(context.Background(), ndpDispatcherContextKey{}, disp)
	if _, err := state.Load(ctx, &buf, restored); err != nil {
		t.Fatalf("Load: %s", err)
	}
	clock := restored.Clock().(*faketime.ManualClock)
	if clock == s.Clock() {
		t.Fatal("restore retained the original clock")
	}
	if got, want := clock.NowMonotonic(), s.Clock().NowMonotonic(); got != want {
		t.Fatalf("restored clock = %s, want %s", got, want)
	}
	// Advancing before Restore also exercises deadlines that have already
	// elapsed when protocol jobs are reconstructed.
	clock.Advance(delay)
	restored.Restore()
	return restored, clock
}

func TestNDPRouteAndPrefixLifetimesAfterRestore(t *testing.T) {
	for _, delay := range []time.Duration{0, 4 * time.Second} {
		t.Run(delay.String(), func(t *testing.T) {
			disp, e, s, clock := newNDPStackForRestore(t, ipv6.NDPConfigurations{
				HandleRAs:                  ipv6.HandlingRAsAlwaysEnabled,
				DiscoverDefaultRouters:     true,
				DiscoverMoreSpecificRoutes: true,
				DiscoverOnLinkPrefixes:     true,
			})
			prefix, subnet, _ := prefixSubnetAddr(0, "")
			infinitePrefix, infiniteSubnet, _ := prefixSubnetAddr(1, "")
			moreSpecific, moreSpecificSubnet, _ := prefixSubnetAddr(2, "")
			e.InjectInbound(header.IPv6ProtocolNumber, raBufSimple(llAddr2, 10))
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithRIO(t, llAddr3, moreSpecific, 10, header.MediumRoutePreference))
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr4, 0, prefix, true, false, 10, 0))
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr4, 0, infinitePrefix, true, false, 10, 0))
			if got := len(disp.offLinkRouteC); got != 2 {
				t.Fatalf("got %d route discovery events, want 2", got)
			}
			if got := len(disp.prefixC); got != 2 {
				t.Fatalf("got %d prefix discovery events, want 2", got)
			}
			for range 2 {
				<-disp.offLinkRouteC
				<-disp.prefixC
			}
			clock.Advance(time.Second)
			// Exercise lifetime updates, including finite-to-infinite conversion.
			e.InjectInbound(header.IPv6ProtocolNumber, raBufSimple(llAddr2, 5))
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithRIO(t, llAddr3, moreSpecific, 5, header.MediumRoutePreference))
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr4, 0, prefix, true, false, 5, 0))
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr4, 0, infinitePrefix, true, false, infiniteVLSeconds, 0))
			clock.Advance(2 * time.Second)
			_, clock = restoreNDPStack(t, s, disp, delay)
			if delay == 0 {
				clock.Advance(3*time.Second - time.Nanosecond)
				if len(disp.offLinkRouteC) != 0 || len(disp.prefixC) != 0 {
					t.Fatal("route or prefix expired before its updated deadline")
				}
				clock.Advance(time.Nanosecond)
			} else {
				clock.RunImmediatelyScheduledJobs()
			}
			wantRoutes := map[tcpip.Subnet]tcpip.Address{
				header.IPv6EmptySubnet: llAddr2,
				moreSpecificSubnet:     llAddr3,
			}
			for range 2 {
				select {
				case event := <-disp.offLinkRouteC:
					if router, ok := wantRoutes[event.subnet]; !ok || event.router != router || event.updated {
						t.Fatalf("unexpected route event: %+v", event)
					}
					delete(wantRoutes, event.subnet)
				default:
					t.Fatal("missing route invalidation after restore")
				}
			}
			select {
			case event := <-disp.prefixC:
				if diff := checkPrefixEvent(event, subnet, false); diff != "" {
					t.Fatal(diff)
				}
			default:
				t.Fatal("missing prefix invalidation after restore")
			}
			clock.Advance(header.NDPInfiniteLifetime)
			select {
			case event := <-disp.prefixC:
				t.Fatalf("infinite prefix %s expired: %+v", infiniteSubnet, event)
			default:
			}
		})
	}
}

func TestNDPSLAACLifetimesAfterRestore(t *testing.T) {
	for _, test := range []struct {
		name       string
		deprecated bool
		delay      time.Duration
	}{
		{name: "preferred"},
		{name: "deprecated", deprecated: true},
		{name: "expired", delay: 9 * time.Second},
	} {
		t.Run(test.name, func(t *testing.T) {
			disp, e, s, clock := newNDPStackForRestore(t, ipv6.NDPConfigurations{
				HandleRAs:              ipv6.HandlingRAsAlwaysEnabled,
				AutoGenGlobalAddresses: true,
			})
			prefix, _, addr := prefixSubnetAddr(0, linkAddr1)
			infinitePrefix, _, infiniteAddr := prefixSubnetAddr(1, linkAddr1)
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, infinitePrefix, false, true, infiniteVLSeconds, infiniteVLSeconds))
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, false, true, 10, 5))
			for _, addr := range []tcpip.AddressWithPrefix{infiniteAddr, addr} {
				if _, err := expectAutoGenAddrNewEvent(disp, addr); err != nil {
					t.Fatal(err)
				}
			}
			elapsed := 2 * time.Second
			if test.deprecated {
				elapsed = 6 * time.Second
			}
			clock.Advance(elapsed)
			if test.deprecated {
				expectAutoGenAddrEvent(t, disp, addr, deprecatedAddr)
			}
			s, clock = restoreNDPStack(t, s, disp, test.delay)
			clock.RunImmediatelyScheduledJobs()
			if test.delay != 0 {
				if containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr) {
					t.Fatal("expired address was retained after restore")
				}
				return
			}
			if len(disp.autoGenAddrC) != 0 {
				t.Fatal("restore repeated a completed deprecation")
			}
			if !test.deprecated {
				clock.Advance(5*time.Second - elapsed - time.Nanosecond)
				if err := checkGetMainNICAddress(s, 1, header.IPv6ProtocolNumber, addr); err != nil {
					t.Fatal(err)
				}
				clock.Advance(time.Nanosecond)
				expectAutoGenAddrEvent(t, disp, addr, deprecatedAddr)
				elapsed = 5 * time.Second
			}
			if err := checkGetMainNICAddress(s, 1, header.IPv6ProtocolNumber, infiniteAddr); err != nil {
				t.Fatal(err)
			}
			clock.Advance(10*time.Second - elapsed)
			expectAutoGenAddrEvent(t, disp, addr, invalidatedAddr)
			if containsV6Addr(s.NICInfo()[1].ProtocolAddresses, addr) {
				t.Fatalf("expired address %s remains assigned", addr)
			}
			clock.Advance(header.NDPInfiniteLifetime)
			if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, infiniteAddr) || len(disp.autoGenAddrC) != 0 {
				t.Fatal("infinite address changed after restore")
			}
		})
	}
}

func TestNDPTemporarySLAACLifetimesAfterRestore(t *testing.T) {
	const regenAdvance = 2 * time.Second
	for _, checkpoint := range []string{"pending", "regenerated", "failed"} {
		t.Run(checkpoint, func(t *testing.T) {
			configs := ipv6.NDPConfigurations{
				HandleRAs:                    ipv6.HandlingRAsAlwaysEnabled,
				AutoGenGlobalAddresses:       true,
				AutoGenTempGlobalAddresses:   true,
				RegenAdvanceDuration:         regenAdvance,
				MaxTempAddrPreferredLifetime: ipv6.MinMaxTempAddrPreferredLifetime,
				MaxTempAddrValidLifetime:     2 * time.Hour,
			}
			disp, e, s, clock := newNDPStackForRestore(t, configs)
			prefix, _, stableAddr := prefixSubnetAddr(0, linkAddr1)
			var history [header.IIDSize]byte
			header.InitialTempIID(history[:], nil, 1)
			tempAddr := header.GenerateTempIPv6SLAACAddr(history[:], stableAddr.Address)
			nextTempAddr := header.GenerateTempIPv6SLAACAddr(history[:], stableAddr.Address)
			e.InjectInbound(header.IPv6ProtocolNumber, raBufWithPI(llAddr2, 0, prefix, false, true, 10000, 10000))
			for _, addr := range []tcpip.AddressWithPrefix{stableAddr, tempAddr} {
				if _, err := expectAutoGenAddrNewEvent(disp, addr); err != nil {
					t.Fatal(err)
				}
			}
			networkEP, err := s.GetNetworkEndpoint(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("GetNetworkEndpoint: %s", err)
			}
			addrEP := networkEP.(stack.AddressableEndpoint).AcquireAssignedAddress(tempAddr.Address, false /* allowTemp */, stack.NeverPrimaryEndpoint, false /* readOnly */)
			if addrEP == nil {
				t.Fatal("temporary address is not assigned")
			}
			lifetimes := addrEP.Lifetimes()
			addrEP.DecRef()
			regenAt := lifetimes.PreferredUntil.Add(-regenAdvance)
			if checkpoint == "failed" {
				// Let the pending callback run without generating an address, then
				// re-enable generation. Restore must not retry that completed job.
				configs.AutoGenTempGlobalAddresses = false
				networkEP.(ipv6.NDPEndpoint).SetNDPConfigurations(configs)
			}
			if checkpoint == "pending" {
				clock.Advance(time.Second)
			} else {
				clock.Advance(regenAt.Sub(clock.NowMonotonic()))
				if checkpoint == "regenerated" {
					if _, err := expectAutoGenAddrNewEvent(disp, nextTempAddr); err != nil {
						t.Fatal(err)
					}
				} else {
					configs.AutoGenTempGlobalAddresses = true
					networkEP.(ipv6.NDPEndpoint).SetNDPConfigurations(configs)
				}
			}
			s, clock = restoreNDPStack(t, s, disp, 0)
			clock.RunImmediatelyScheduledJobs()
			if len(disp.autoGenAddrNewC) != 0 {
				t.Fatal("restore repeated a completed regeneration")
			}
			if checkpoint == "pending" {
				clock.Advance(regenAt.Sub(clock.NowMonotonic()) - time.Nanosecond)
				if len(disp.autoGenAddrNewC) != 0 {
					t.Fatal("temporary address regenerated before its deadline")
				}
				clock.Advance(time.Nanosecond)
				if _, err := expectAutoGenAddrNewEvent(disp, nextTempAddr); err != nil {
					t.Fatal(err)
				}
			}
			clock.Advance(regenAdvance)
			expectAutoGenAddrEvent(t, disp, tempAddr, deprecatedAddr)
			// Stop subsequent generations while checking the original address's
			// valid lifetime independently of the prefix's longer lifetime.
			configs.AutoGenTempGlobalAddresses = false
			networkEP, err = s.GetNetworkEndpoint(1, header.IPv6ProtocolNumber)
			if err != nil {
				t.Fatalf("GetNetworkEndpoint: %s", err)
			}
			networkEP.(ipv6.NDPEndpoint).SetNDPConfigurations(configs)
			clock.Advance(lifetimes.ValidUntil.Sub(clock.NowMonotonic()) - time.Nanosecond)
			if !containsV6Addr(s.NICInfo()[1].ProtocolAddresses, tempAddr) {
				t.Fatal("temporary address invalidated before its deadline")
			}
			clock.Advance(time.Nanosecond)
			if containsV6Addr(s.NICInfo()[1].ProtocolAddresses, tempAddr) {
				t.Fatal("temporary address remains assigned after its deadline")
			}
		})
	}
}
