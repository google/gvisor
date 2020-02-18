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

// waiterUnlock is called from g0, so when the race detector is enabled,
// waiterUnlock must be implemented in assembly since no race context is
// available.
//
// +build !race
// +build !amd64,!arm64

package syncevent

import (
	"sync/atomic"
	"unsafe"
)

// waiterUnlock is the "unlock function" passed to runtime.gopark by
// Waiter.Wait*. wg is &Waiter.g, and g is a pointer to the calling runtime.g.
// waiterUnlock returns true if Waiter.Wait should sleep and false if sleeping
// should be aborted.
//
//go:nosplit
func waiterUnlock(g unsafe.Pointer, wg *unsafe.Pointer) bool {
	// The only way this CAS can fail is if a call to Waiter.NotifyPending()
	// has replaced *wg with nil, in which case we should not sleep.
	return atomic.CompareAndSwapPointer(wg, (unsafe.Pointer)(&preparingG), g)
}
