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

package systrap

import (
	"testing"
	"unsafe"

	"gvisor.dev/gvisor/pkg/hostarch"
)

// TestContextQueueLayout ensures layout consistency of contextQueue.
func TestContextQueueLayout(t *testing.T) {
	var q contextQueue
	const line = uintptr(hostarch.CacheLineSize)
	for _, tc := range []struct {
		field string
		got   uintptr
		want  uintptr
	}{
		{"end", unsafe.Offsetof(q.end), 0 * line},
		{"start", unsafe.Offsetof(q.start), 1 * line},
		{"fastPathDisabled", unsafe.Offsetof(q.fastPathDisabled), 2 * line},
		{"numAwakeContexts", unsafe.Offsetof(q.numAwakeContexts), 2*line + 4},
		{"numActiveThreads", unsafe.Offsetof(q.numActiveThreads), 3 * line},
		{"numSpinningThreads", unsafe.Offsetof(q.numSpinningThreads), 3*line + 4},
		{"numThreadsToWakeup", unsafe.Offsetof(q.numThreadsToWakeup), 4 * line},
		{"numActiveContexts", unsafe.Offsetof(q.numActiveContexts), 5 * line},
		{"usedFastPath", unsafe.Offsetof(q.usedFastPath), 5*line + 4},
		{"ringbuffer", unsafe.Offsetof(q.ringbuffer), 6 * line},
	} {
		if tc.got != tc.want {
			t.Errorf("unsafe.Offsetof(contextQueue.%s) = %d, want %d", tc.field, tc.got, tc.want)
		}
	}
	if got, want := unsafe.Sizeof(q), 6*line+uintptr(maxContextQueueEntries)*8; got != want {
		t.Errorf("unsafe.Sizeof(contextQueue{}) = %d, want %d", got, want)
	}
	// Go's sync/atomic requires 64-bit words to be 8-byte aligned.
	if off := unsafe.Offsetof(q.ringbuffer); off%8 != 0 {
		t.Errorf("ringbuffer offset %d is not 8-byte aligned", off)
	}
}
