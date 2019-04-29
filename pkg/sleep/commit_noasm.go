// Copyright 2018 The gVisor Authors.
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

// +build !race
// +build !amd64

package sleep

import "sync/atomic"

// commitSleep signals to wakers that the given g is now sleeping. Wakers can
// then fetch it and wake it.
//
// The commit may fail if wakers have been asserted after our last check, in
// which case they will have set s.waitingG to zero.
//
// It is written in assembly because it is called from g0, so it doesn't have
// a race context.
func commitSleep(g uintptr, waitingG *uintptr) bool {
	for {
		// Check if the wait was aborted.
		if atomic.LoadUintptr(waitingG) == 0 {
			return false
		}

		// Try to store the G so that wakers know who to wake.
		if atomic.CompareAndSwapUintptr(waitingG, preparingG, g) {
			return true
		}
	}
}
