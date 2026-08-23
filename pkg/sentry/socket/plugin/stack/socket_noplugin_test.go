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

//go:build !network_plugins

package stack

import (
	"testing"

	"gvisor.dev/gvisor/pkg/waiter"
)

func TestReadinessFallback(t *testing.T) {
	const highBit = waiter.EventMask(1 << 40)
	for _, tc := range []struct {
		name  string
		ready waiter.EventMask
		mask  waiter.EventMask
	}{
		{name: "hangup with empty cache", mask: waiter.EventHUp},
		{name: "error with populated cache", ready: waiter.EventErr | waiter.EventIn | highBit, mask: waiter.EventErr},
		{name: "empty mask", ready: waiter.EventIn | highBit},
		{name: "missing IO bit", ready: waiter.EventOut | highBit, mask: waiter.EventIn},
		{name: "partial IO hit", ready: waiter.EventIn | waiter.EventErr | highBit, mask: waiter.EventIn | waiter.EventOut | waiter.EventErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var s socketOperations
			s.eventInfo.Ready.Store(uint64(tc.ready))
			// Without a plugin, cgo.Readiness panics. This verifies that
			// requests the cache cannot answer reach the backend entrypoint.
			defer func() {
				if got := recover(); got != "unimplemented" {
					t.Errorf("Readiness(%#x) panic = %v, want unimplemented", tc.mask, got)
				}
				if got := s.eventInfo.Ready.Load(); got != uint64(tc.ready) {
					t.Errorf("cached readiness = %#x, want %#x", got, tc.ready)
				}
			}()
			s.Readiness(tc.mask)
		})
	}
}
