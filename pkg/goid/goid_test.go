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

package goid

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestUniquenessAndConsistency(t *testing.T) {
	const (
		numGoroutines = 5000

		// maxID is not an intrinsic property of goroutine IDs; it is only a
		// property of how the Go runtime currently assigns them. Future
		// changes to the Go runtime may require that maxID be raised, or that
		// assertions regarding it be removed entirely.
		maxID = numGoroutines + 1000
	)

	var (
		goidsMu   sync.Mutex
		goids     = make(map[int64]struct{})
		checkedWG sync.WaitGroup
		exitCh    = make(chan struct{})
	)
	for i := 0; i < numGoroutines; i++ {
		checkedWG.Add(1)
		go func() {
			id := Get()
			if id > maxID {
				t.Errorf("observed unexpectedly large goroutine ID %d", id)
			}
			goidsMu.Lock()
			if _, dup := goids[id]; dup {
				t.Errorf("observed duplicate goroutine ID %d", id)
			}
			goids[id] = struct{}{}
			goidsMu.Unlock()
			checkedWG.Done()
			for {
				if curID := Get(); curID != id {
					t.Errorf("goroutine ID changed from %d to %d", id, curID)
					// Don't spam logs by repeating the check; wait quietly for
					// the test to finish.
					<-exitCh
					return
				}
				// Check if the test is over.
				select {
				case <-exitCh:
					return
				default:
				}
				// Yield to other goroutines, and possibly migrate to another P.
				runtime.Gosched()
			}
		}()
	}
	// Wait for all goroutines to perform uniqueness checks.
	checkedWG.Wait()
	// Wait for an additional second to allow goroutines to spin checking for
	// ID consistency.
	time.Sleep(time.Second)
	// Request that all goroutines exit.
	close(exitCh)
}
