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
	"sync"
	"testing"

	"gvisor.dev/gvisor/pkg/waiter"
)

func TestConcurrentReadiness(t *testing.T) {
	const common = waiter.EventErr | waiter.EventHUp | waiter.EventMask(1<<40)
	const initial = waiter.EventIn | waiter.EventOut | common
	var s socketOperations
	s.eventInfo.Ready.Store(uint64(initial))

	// Each caller consumes a different I/O bit, so neither needs to query C.
	masks := [...]waiter.EventMask{waiter.EventIn | common, waiter.EventOut | common}
	var got [len(masks)]waiter.EventMask
	var wg sync.WaitGroup
	for i, mask := range masks {
		wg.Go(func() {
			got[i] = s.Readiness(mask)
		})
	}
	wg.Wait()
	for i, mask := range masks {
		if got[i] != mask {
			t.Errorf("Readiness(%#x) = %#x, want %#x", mask, got[i], mask)
		}
	}
	if got := s.Readiness(common); got != common {
		t.Errorf("Readiness(%#x) = %#x, want %#x", common, got, common)
	}
}
