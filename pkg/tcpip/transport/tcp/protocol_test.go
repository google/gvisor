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

package tcp

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// TestDefaultKeepaliveSettings verifies that default keepalive settings
// can be set and retrieved correctly.
func TestDefaultKeepaliveSettings(t *testing.T) {
	s := stack.New(stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
	})
	defer s.Close()

	p := protocolFromStack(s)

	// Test default values
	if got := p.DefaultKeepaliveIdle(); got != DefaultKeepaliveIdle {
		t.Errorf("DefaultKeepaliveIdle() = %v, want %v", got, DefaultKeepaliveIdle)
	}
	if got := p.DefaultKeepaliveInterval(); got != DefaultKeepaliveInterval {
		t.Errorf("DefaultKeepaliveInterval() = %v, want %v", got, DefaultKeepaliveInterval)
	}
	if got := p.DefaultKeepaliveCount(); got != DefaultKeepaliveCount {
		t.Errorf("DefaultKeepaliveCount() = %v, want %v", got, DefaultKeepaliveCount)
	}

	// Test setting custom values
	customIdle := 60 * time.Second
	customInterval := 10 * time.Second
	customCount := 5

	p.SetDefaultKeepaliveIdle(customIdle)
	p.SetDefaultKeepaliveInterval(customInterval)
	p.SetDefaultKeepaliveCount(customCount)

	if got := p.DefaultKeepaliveIdle(); got != customIdle {
		t.Errorf("after Set, DefaultKeepaliveIdle() = %v, want %v", got, customIdle)
	}
	if got := p.DefaultKeepaliveInterval(); got != customInterval {
		t.Errorf("after Set, DefaultKeepaliveInterval() = %v, want %v", got, customInterval)
	}
	if got := p.DefaultKeepaliveCount(); got != customCount {
		t.Errorf("after Set, DefaultKeepaliveCount() = %v, want %v", got, customCount)
	}
}

// TestNewEndpointUsesDefaultKeepalive verifies that new endpoints
// use the protocol's default keepalive settings.
func TestNewEndpointUsesDefaultKeepalive(t *testing.T) {
	s := stack.New(stack.Options{
		TransportProtocols: []stack.TransportProtocolFactory{NewProtocol},
	})
	defer s.Close()

	p := protocolFromStack(s)

	// Set custom defaults
	customIdle := 45 * time.Second
	customInterval := 15 * time.Second
	customCount := 7

	p.SetDefaultKeepaliveIdle(customIdle)
	p.SetDefaultKeepaliveInterval(customInterval)
	p.SetDefaultKeepaliveCount(customCount)

	// Create a new endpoint
	ep := newEndpoint(s, p, 0, nil)
	defer ep.Close()

	// Verify the endpoint inherited the defaults
	if got := ep.keepalive.idle; got != customIdle {
		t.Errorf("endpoint keepalive.idle = %v, want %v", got, customIdle)
	}
	if got := ep.keepalive.interval; got != customInterval {
		t.Errorf("endpoint keepalive.interval = %v, want %v", got, customInterval)
	}
	if got := ep.keepalive.count; got != customCount {
		t.Errorf("endpoint keepalive.count = %v, want %v", got, customCount)
	}
}
