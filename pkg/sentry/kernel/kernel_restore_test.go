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

package kernel

import (
	"errors"
	"runtime"
	"testing"
	"time"
)

func TestCheckpointRegistrationDuringNotification(t *testing.T) {
	var k Kernel
	w := &k.CheckpointWait
	w.k = &k
	gen := CheckpointGeneration{Count: 1}
	wantErr := errors.New("checkpoint failed")
	type result struct {
		gen CheckpointGeneration
		err error
	}
	results := make(chan result, 2)
	registered := make(chan any, 1)
	notified := make(chan struct{})

	// Hold the generation lock as a checkpoint producer does. Registration
	// must not hold the waiters lock while waiting to read this generation.
	k.checkpointMu.Lock()
	k.checkpointGen = gen
	go func() {
		registered <- w.Register(func(gen CheckpointGeneration, err error) {
			results <- result{gen, err}
		}, gen.Count)
	}()
	go func() {
		for {
			w.mu.Lock()
			pending := len(w.waiters) != 0
			w.mu.Unlock()
			if pending {
				break
			}
			runtime.Gosched()
		}
		w.signal(gen, wantErr)
		close(notified)
	}()

	// Mutex contention is not durably blocking in synctest, so its clock
	// cannot advance a watchdog when the original lock inversion occurs.
	// Use a real-time deadline to release both goroutines on that failure.
	var blocked bool
	select {
	case <-notified:
	case <-time.After(5 * time.Second):
		blocked = true
	}
	// Release the generation lock even on failure, so the original lock
	// inversion cannot strand either goroutine during test cleanup.
	k.checkpointMu.Unlock()
	key := <-registered
	<-notified
	w.Unregister(key)
	if blocked {
		t.Fatal("checkpoint notification blocked on registration")
	}
	if len(results) != 1 {
		t.Fatalf("got %d callbacks, want 1", len(results))
	}
	if got := <-results; got.gen != gen || got.err != wantErr {
		t.Fatalf("callback = (%+v, %v), want (%+v, %v)", got.gen, got.err, gen, wantErr)
	}
}
