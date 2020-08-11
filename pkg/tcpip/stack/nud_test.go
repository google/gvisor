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

package stack_test

import (
	"math"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	defaultBaseReachableTime           = 30 * time.Second
	minimumBaseReachableTime           = time.Millisecond
	defaultMinRandomFactor             = 0.5
	defaultMaxRandomFactor             = 1.5
	defaultRetransmitTimer             = time.Second
	minimumRetransmitTimer             = time.Millisecond
	defaultDelayFirstProbeTime         = 5 * time.Second
	defaultMaxMulticastProbes          = 3
	defaultMaxUnicastProbes            = 3
	defaultMaxAnycastDelayTime         = time.Second
	defaultMaxReachbilityConfirmations = 3
	defaultUnreachableTime             = 5 * time.Second

	defaultFakeRandomNum = 0.5
)

// fakeRand is a deterministic random number generator.
type fakeRand struct {
	num float32
}

var _ stack.Rand = (*fakeRand)(nil)

func (f *fakeRand) Float32() float32 {
	return f.num
}

// TestSetNUDConfigurationFailsForBadNICID tests to make sure we get an error if
// we attempt to update NUD configurations using an invalid NICID.
func TestSetNUDConfigurationFailsForBadNICID(t *testing.T) {
	s := stack.New(stack.Options{
		// A neighbor cache is required to store NUDConfigurations. The networking
		// stack will only allocate neighbor caches if a protocol providing link
		// address resolution is specified (e.g. ARP or IPv6).
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
	})

	// No NIC with ID 1 yet.
	config := stack.NUDConfigurations{}
	if err := s.SetNUDConfigurations(1, config); err != tcpip.ErrUnknownNICID {
		t.Fatalf("got s.SetNDPConfigurations(1, %+v) = %v, want = %s", config, err, tcpip.ErrUnknownNICID)
	}
}

// TestNUDConfigurationFailsForNotSupported tests to make sure we get a
// NotSupported error if we attempt to retrieve NUD configurations when the
// stack doesn't support NUD.
//
// The stack will report to not support NUD if a neighbor cache for a given NIC
// is not allocated. The networking stack will only allocate neighbor caches if
// a protocol providing link address resolution is specified (e.g. ARP, IPv6).
func TestNUDConfigurationFailsForNotSupported(t *testing.T) {
	const nicID = 1

	e := channel.New(0, 1280, linkAddr1)
	e.LinkEPCapabilities |= stack.CapabilityResolutionRequired

	s := stack.New(stack.Options{
		NUDConfigs: stack.DefaultNUDConfigurations(),
	})
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}
	if _, err := s.NUDConfigurations(nicID); err != tcpip.ErrNotSupported {
		t.Fatalf("got s.NDPConfigurations(%d) = %v, want = %s", nicID, err, tcpip.ErrNotSupported)
	}
}

// TestNUDConfigurationFailsForNotSupported tests to make sure we get a
// NotSupported error if we attempt to set NUD configurations when the stack
// doesn't support NUD.
//
// The stack will report to not support NUD if a neighbor cache for a given NIC
// is not allocated. The networking stack will only allocate neighbor caches if
// a protocol providing link address resolution is specified (e.g. ARP, IPv6).
func TestSetNUDConfigurationFailsForNotSupported(t *testing.T) {
	const nicID = 1

	e := channel.New(0, 1280, linkAddr1)
	e.LinkEPCapabilities |= stack.CapabilityResolutionRequired

	s := stack.New(stack.Options{
		NUDConfigs: stack.DefaultNUDConfigurations(),
	})
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}

	config := stack.NUDConfigurations{}
	if err := s.SetNUDConfigurations(nicID, config); err != tcpip.ErrNotSupported {
		t.Fatalf("got s.SetNDPConfigurations(%d, %+v) = %v, want = %s", nicID, config, err, tcpip.ErrNotSupported)
	}
}

// TestDefaultNUDConfigurationIsValid verifies that calling
// resetInvalidFields() on the result of DefaultNUDConfigurations() does not
// change anything. DefaultNUDConfigurations() should return a valid
// NUDConfigurations.
func TestDefaultNUDConfigurations(t *testing.T) {
	const nicID = 1

	e := channel.New(0, 1280, linkAddr1)
	e.LinkEPCapabilities |= stack.CapabilityResolutionRequired

	s := stack.New(stack.Options{
		// A neighbor cache is required to store NUDConfigurations. The networking
		// stack will only allocate neighbor caches if a protocol providing link
		// address resolution is specified (e.g. ARP or IPv6).
		NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
		NUDConfigs:       stack.DefaultNUDConfigurations(),
	})
	if err := s.CreateNIC(nicID, e); err != nil {
		t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
	}
	c, err := s.NUDConfigurations(nicID)
	if err != nil {
		t.Fatalf("got stack.NUDConfigurations(%d) = %s", nicID, err)
	}
	if got, want := c, stack.DefaultNUDConfigurations(); got != want {
		t.Errorf("got stack.NUDConfigurations(%d) = %+v, want = %+v", nicID, got, want)
	}
}

func TestNUDConfigurationsBaseReachableTime(t *testing.T) {
	tests := []struct {
		name              string
		baseReachableTime time.Duration
		want              time.Duration
	}{
		// Invalid cases
		{
			name:              "EqualToZero",
			baseReachableTime: 0,
			want:              defaultBaseReachableTime,
		},
		// Valid cases
		{
			name:              "MoreThanZero",
			baseReachableTime: time.Millisecond,
			want:              time.Millisecond,
		},
		{
			name:              "MoreThanDefaultBaseReachableTime",
			baseReachableTime: 2 * defaultBaseReachableTime,
			want:              2 * defaultBaseReachableTime,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const nicID = 1

			c := stack.DefaultNUDConfigurations()
			c.BaseReachableTime = test.baseReachableTime

			e := channel.New(0, 1280, linkAddr1)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired

			s := stack.New(stack.Options{
				// A neighbor cache is required to store NUDConfigurations. The
				// networking stack will only allocate neighbor caches if a protocol
				// providing link address resolution is specified (e.g. ARP or IPv6).
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NUDConfigs:       c,
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			sc, err := s.NUDConfigurations(nicID)
			if err != nil {
				t.Fatalf("got stack.NUDConfigurations(%d) = %s", nicID, err)
			}
			if got := sc.BaseReachableTime; got != test.want {
				t.Errorf("got BaseReachableTime = %q, want = %q", got, test.want)
			}
		})
	}
}

func TestNUDConfigurationsMinRandomFactor(t *testing.T) {
	tests := []struct {
		name            string
		minRandomFactor float32
		want            float32
	}{
		// Invalid cases
		{
			name:            "LessThanZero",
			minRandomFactor: -1,
			want:            defaultMinRandomFactor,
		},
		{
			name:            "EqualToZero",
			minRandomFactor: 0,
			want:            defaultMinRandomFactor,
		},
		// Valid cases
		{
			name:            "MoreThanZero",
			minRandomFactor: 1,
			want:            1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const nicID = 1

			c := stack.DefaultNUDConfigurations()
			c.MinRandomFactor = test.minRandomFactor

			e := channel.New(0, 1280, linkAddr1)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired

			s := stack.New(stack.Options{
				// A neighbor cache is required to store NUDConfigurations. The
				// networking stack will only allocate neighbor caches if a protocol
				// providing link address resolution is specified (e.g. ARP or IPv6).
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NUDConfigs:       c,
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			sc, err := s.NUDConfigurations(nicID)
			if err != nil {
				t.Fatalf("got stack.NUDConfigurations(%d) = %s", nicID, err)
			}
			if got := sc.MinRandomFactor; got != test.want {
				t.Errorf("got MinRandomFactor = %f, want = %f", got, test.want)
			}
		})
	}
}

func TestNUDConfigurationsMaxRandomFactor(t *testing.T) {
	tests := []struct {
		name            string
		minRandomFactor float32
		maxRandomFactor float32
		want            float32
	}{
		// Invalid cases
		{
			name:            "LessThanZero",
			minRandomFactor: defaultMinRandomFactor,
			maxRandomFactor: -1,
			want:            defaultMaxRandomFactor,
		},
		{
			name:            "EqualToZero",
			minRandomFactor: defaultMinRandomFactor,
			maxRandomFactor: 0,
			want:            defaultMaxRandomFactor,
		},
		{
			name:            "LessThanMinRandomFactor",
			minRandomFactor: defaultMinRandomFactor,
			maxRandomFactor: defaultMinRandomFactor * 0.99,
			want:            defaultMaxRandomFactor,
		},
		{
			name:            "MoreThanMinRandomFactorWhenMinRandomFactorIsLargerThanMaxRandomFactorDefault",
			minRandomFactor: defaultMaxRandomFactor * 2,
			maxRandomFactor: defaultMaxRandomFactor,
			want:            defaultMaxRandomFactor * 6,
		},
		// Valid cases
		{
			name:            "EqualToMinRandomFactor",
			minRandomFactor: defaultMinRandomFactor,
			maxRandomFactor: defaultMinRandomFactor,
			want:            defaultMinRandomFactor,
		},
		{
			name:            "MoreThanMinRandomFactor",
			minRandomFactor: defaultMinRandomFactor,
			maxRandomFactor: defaultMinRandomFactor * 1.1,
			want:            defaultMinRandomFactor * 1.1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const nicID = 1

			c := stack.DefaultNUDConfigurations()
			c.MinRandomFactor = test.minRandomFactor
			c.MaxRandomFactor = test.maxRandomFactor

			e := channel.New(0, 1280, linkAddr1)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired

			s := stack.New(stack.Options{
				// A neighbor cache is required to store NUDConfigurations. The
				// networking stack will only allocate neighbor caches if a protocol
				// providing link address resolution is specified (e.g. ARP or IPv6).
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NUDConfigs:       c,
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			sc, err := s.NUDConfigurations(nicID)
			if err != nil {
				t.Fatalf("got stack.NUDConfigurations(%d) = %s", nicID, err)
			}
			if got := sc.MaxRandomFactor; got != test.want {
				t.Errorf("got MaxRandomFactor = %f, want = %f", got, test.want)
			}
		})
	}
}

func TestNUDConfigurationsRetransmitTimer(t *testing.T) {
	tests := []struct {
		name            string
		retransmitTimer time.Duration
		want            time.Duration
	}{
		// Invalid cases
		{
			name:            "EqualToZero",
			retransmitTimer: 0,
			want:            defaultRetransmitTimer,
		},
		{
			name:            "LessThanMinimumRetransmitTimer",
			retransmitTimer: minimumRetransmitTimer - time.Nanosecond,
			want:            defaultRetransmitTimer,
		},
		// Valid cases
		{
			name:            "EqualToMinimumRetransmitTimer",
			retransmitTimer: minimumRetransmitTimer,
			want:            minimumBaseReachableTime,
		},
		{
			name:            "LargetThanMinimumRetransmitTimer",
			retransmitTimer: 2 * minimumBaseReachableTime,
			want:            2 * minimumBaseReachableTime,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const nicID = 1

			c := stack.DefaultNUDConfigurations()
			c.RetransmitTimer = test.retransmitTimer

			e := channel.New(0, 1280, linkAddr1)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired

			s := stack.New(stack.Options{
				// A neighbor cache is required to store NUDConfigurations. The
				// networking stack will only allocate neighbor caches if a protocol
				// providing link address resolution is specified (e.g. ARP or IPv6).
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NUDConfigs:       c,
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			sc, err := s.NUDConfigurations(nicID)
			if err != nil {
				t.Fatalf("got stack.NUDConfigurations(%d) = %s", nicID, err)
			}
			if got := sc.RetransmitTimer; got != test.want {
				t.Errorf("got RetransmitTimer = %q, want = %q", got, test.want)
			}
		})
	}
}

func TestNUDConfigurationsDelayFirstProbeTime(t *testing.T) {
	tests := []struct {
		name                string
		delayFirstProbeTime time.Duration
		want                time.Duration
	}{
		// Invalid cases
		{
			name:                "EqualToZero",
			delayFirstProbeTime: 0,
			want:                defaultDelayFirstProbeTime,
		},
		// Valid cases
		{
			name:                "MoreThanZero",
			delayFirstProbeTime: time.Millisecond,
			want:                time.Millisecond,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const nicID = 1

			c := stack.DefaultNUDConfigurations()
			c.DelayFirstProbeTime = test.delayFirstProbeTime

			e := channel.New(0, 1280, linkAddr1)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired

			s := stack.New(stack.Options{
				// A neighbor cache is required to store NUDConfigurations. The
				// networking stack will only allocate neighbor caches if a protocol
				// providing link address resolution is specified (e.g. ARP or IPv6).
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NUDConfigs:       c,
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			sc, err := s.NUDConfigurations(nicID)
			if err != nil {
				t.Fatalf("got stack.NUDConfigurations(%d) = %s", nicID, err)
			}
			if got := sc.DelayFirstProbeTime; got != test.want {
				t.Errorf("got DelayFirstProbeTime = %q, want = %q", got, test.want)
			}
		})
	}
}

func TestNUDConfigurationsMaxMulticastProbes(t *testing.T) {
	tests := []struct {
		name               string
		maxMulticastProbes uint32
		want               uint32
	}{
		// Invalid cases
		{
			name:               "EqualToZero",
			maxMulticastProbes: 0,
			want:               defaultMaxMulticastProbes,
		},
		// Valid cases
		{
			name:               "MoreThanZero",
			maxMulticastProbes: 1,
			want:               1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const nicID = 1

			c := stack.DefaultNUDConfigurations()
			c.MaxMulticastProbes = test.maxMulticastProbes

			e := channel.New(0, 1280, linkAddr1)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired

			s := stack.New(stack.Options{
				// A neighbor cache is required to store NUDConfigurations. The
				// networking stack will only allocate neighbor caches if a protocol
				// providing link address resolution is specified (e.g. ARP or IPv6).
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NUDConfigs:       c,
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			sc, err := s.NUDConfigurations(nicID)
			if err != nil {
				t.Fatalf("got stack.NUDConfigurations(%d) = %s", nicID, err)
			}
			if got := sc.MaxMulticastProbes; got != test.want {
				t.Errorf("got MaxMulticastProbes = %q, want = %q", got, test.want)
			}
		})
	}
}

func TestNUDConfigurationsMaxUnicastProbes(t *testing.T) {
	tests := []struct {
		name             string
		maxUnicastProbes uint32
		want             uint32
	}{
		// Invalid cases
		{
			name:             "EqualToZero",
			maxUnicastProbes: 0,
			want:             defaultMaxUnicastProbes,
		},
		// Valid cases
		{
			name:             "MoreThanZero",
			maxUnicastProbes: 1,
			want:             1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const nicID = 1

			c := stack.DefaultNUDConfigurations()
			c.MaxUnicastProbes = test.maxUnicastProbes

			e := channel.New(0, 1280, linkAddr1)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired

			s := stack.New(stack.Options{
				// A neighbor cache is required to store NUDConfigurations. The
				// networking stack will only allocate neighbor caches if a protocol
				// providing link address resolution is specified (e.g. ARP or IPv6).
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NUDConfigs:       c,
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			sc, err := s.NUDConfigurations(nicID)
			if err != nil {
				t.Fatalf("got stack.NUDConfigurations(%d) = %s", nicID, err)
			}
			if got := sc.MaxUnicastProbes; got != test.want {
				t.Errorf("got MaxUnicastProbes = %q, want = %q", got, test.want)
			}
		})
	}
}

func TestNUDConfigurationsUnreachableTime(t *testing.T) {
	tests := []struct {
		name            string
		unreachableTime time.Duration
		want            time.Duration
	}{
		// Invalid cases
		{
			name:            "EqualToZero",
			unreachableTime: 0,
			want:            defaultUnreachableTime,
		},
		// Valid cases
		{
			name:            "MoreThanZero",
			unreachableTime: time.Millisecond,
			want:            time.Millisecond,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			const nicID = 1

			c := stack.DefaultNUDConfigurations()
			c.UnreachableTime = test.unreachableTime

			e := channel.New(0, 1280, linkAddr1)
			e.LinkEPCapabilities |= stack.CapabilityResolutionRequired

			s := stack.New(stack.Options{
				// A neighbor cache is required to store NUDConfigurations. The
				// networking stack will only allocate neighbor caches if a protocol
				// providing link address resolution is specified (e.g. ARP or IPv6).
				NetworkProtocols: []stack.NetworkProtocol{ipv6.NewProtocol()},
				NUDConfigs:       c,
			})
			if err := s.CreateNIC(nicID, e); err != nil {
				t.Fatalf("CreateNIC(%d, _) = %s", nicID, err)
			}
			sc, err := s.NUDConfigurations(nicID)
			if err != nil {
				t.Fatalf("got stack.NUDConfigurations(%d) = %s", nicID, err)
			}
			if got := sc.UnreachableTime; got != test.want {
				t.Errorf("got UnreachableTime = %q, want = %q", got, test.want)
			}
		})
	}
}

// TestNUDStateReachableTime verifies the correctness of the ReachableTime
// computation.
func TestNUDStateReachableTime(t *testing.T) {
	tests := []struct {
		name              string
		baseReachableTime time.Duration
		minRandomFactor   float32
		maxRandomFactor   float32
		want              time.Duration
	}{
		{
			name:              "AllZeros",
			baseReachableTime: 0,
			minRandomFactor:   0,
			maxRandomFactor:   0,
			want:              0,
		},
		{
			name:              "ZeroMaxRandomFactor",
			baseReachableTime: time.Second,
			minRandomFactor:   0,
			maxRandomFactor:   0,
			want:              0,
		},
		{
			name:              "ZeroMinRandomFactor",
			baseReachableTime: time.Second,
			minRandomFactor:   0,
			maxRandomFactor:   1,
			want:              time.Duration(defaultFakeRandomNum * float32(time.Second)),
		},
		{
			name:              "FractionalRandomFactor",
			baseReachableTime: time.Duration(math.MaxInt64),
			minRandomFactor:   0.001,
			maxRandomFactor:   0.002,
			want:              time.Duration((0.001 + (0.001 * defaultFakeRandomNum)) * float32(math.MaxInt64)),
		},
		{
			name:              "MinAndMaxRandomFactorsEqual",
			baseReachableTime: time.Second,
			minRandomFactor:   1,
			maxRandomFactor:   1,
			want:              time.Second,
		},
		{
			name:              "MinAndMaxRandomFactorsDifferent",
			baseReachableTime: time.Second,
			minRandomFactor:   1,
			maxRandomFactor:   2,
			want:              time.Duration((1.0 + defaultFakeRandomNum) * float32(time.Second)),
		},
		{
			name:              "MaxInt64",
			baseReachableTime: time.Duration(math.MaxInt64),
			minRandomFactor:   1,
			maxRandomFactor:   1,
			want:              time.Duration(math.MaxInt64),
		},
		{
			name:              "Overflow",
			baseReachableTime: time.Duration(math.MaxInt64),
			minRandomFactor:   1.5,
			maxRandomFactor:   1.5,
			want:              time.Duration(math.MaxInt64),
		},
		{
			name:              "DoubleOverflow",
			baseReachableTime: time.Duration(math.MaxInt64),
			minRandomFactor:   2.5,
			maxRandomFactor:   2.5,
			want:              time.Duration(math.MaxInt64),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := stack.NUDConfigurations{
				BaseReachableTime: test.baseReachableTime,
				MinRandomFactor:   test.minRandomFactor,
				MaxRandomFactor:   test.maxRandomFactor,
			}
			// A fake random number generator is used to ensure deterministic
			// results.
			rng := fakeRand{
				num: defaultFakeRandomNum,
			}
			s := stack.NewNUDState(c, &rng)
			if got, want := s.ReachableTime(), test.want; got != want {
				t.Errorf("got ReachableTime = %q, want = %q", got, want)
			}
		})
	}
}

// TestNUDStateRecomputeReachableTime exercises the ReachableTime function
// twice to verify recomputation of reachable time when the min random factor,
// max random factor, or base reachable time changes.
func TestNUDStateRecomputeReachableTime(t *testing.T) {
	const defaultBase = time.Second
	const defaultMin = 2.0 * defaultMaxRandomFactor
	const defaultMax = 3.0 * defaultMaxRandomFactor

	tests := []struct {
		name              string
		baseReachableTime time.Duration
		minRandomFactor   float32
		maxRandomFactor   float32
		want              time.Duration
	}{
		{
			name:              "BaseReachableTime",
			baseReachableTime: 2 * defaultBase,
			minRandomFactor:   defaultMin,
			maxRandomFactor:   defaultMax,
			want:              time.Duration((defaultMin + (defaultMax-defaultMin)*defaultFakeRandomNum) * float32(2*defaultBase)),
		},
		{
			name:              "MinRandomFactor",
			baseReachableTime: defaultBase,
			minRandomFactor:   defaultMax,
			maxRandomFactor:   defaultMax,
			want:              time.Duration(defaultMax * float32(defaultBase)),
		},
		{
			name:              "MaxRandomFactor",
			baseReachableTime: defaultBase,
			minRandomFactor:   defaultMin,
			maxRandomFactor:   defaultMin,
			want:              time.Duration(defaultMin * float32(defaultBase)),
		},
		{
			name:              "BothRandomFactor",
			baseReachableTime: defaultBase,
			minRandomFactor:   2 * defaultMin,
			maxRandomFactor:   2 * defaultMax,
			want:              time.Duration((2*defaultMin + (2*defaultMax-2*defaultMin)*defaultFakeRandomNum) * float32(defaultBase)),
		},
		{
			name:              "BaseReachableTimeAndBothRandomFactors",
			baseReachableTime: 2 * defaultBase,
			minRandomFactor:   2 * defaultMin,
			maxRandomFactor:   2 * defaultMax,
			want:              time.Duration((2*defaultMin + (2*defaultMax-2*defaultMin)*defaultFakeRandomNum) * float32(2*defaultBase)),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := stack.DefaultNUDConfigurations()
			c.BaseReachableTime = defaultBase
			c.MinRandomFactor = defaultMin
			c.MaxRandomFactor = defaultMax

			// A fake random number generator is used to ensure deterministic
			// results.
			rng := fakeRand{
				num: defaultFakeRandomNum,
			}
			s := stack.NewNUDState(c, &rng)
			old := s.ReachableTime()

			if got, want := s.ReachableTime(), old; got != want {
				t.Errorf("got ReachableTime = %q, want = %q", got, want)
			}

			// Check for recomputation when changing the min random factor, the max
			// random factor, the base reachability time, or any permutation of those
			// three options.
			c.BaseReachableTime = test.baseReachableTime
			c.MinRandomFactor = test.minRandomFactor
			c.MaxRandomFactor = test.maxRandomFactor
			s.SetConfig(c)

			if got, want := s.ReachableTime(), test.want; got != want {
				t.Errorf("got ReachableTime = %q, want = %q", got, want)
			}

			// Verify that ReachableTime isn't recomputed when none of the
			// configuration options change. The random factor is changed so that if
			// a recompution were to occur, ReachableTime would change.
			rng.num = defaultFakeRandomNum / 2.0
			if got, want := s.ReachableTime(), test.want; got != want {
				t.Errorf("got ReachableTime = %q, want = %q", got, want)
			}
		})
	}
}
