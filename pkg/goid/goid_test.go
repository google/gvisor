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

// +build race

package goid

import (
	"runtime"
	"sync"
	"testing"
)

func TestInitialGoID(t *testing.T) {
	const max = 10000
	if id := goid(); id < 0 || id > max {
		t.Errorf("got goid = %d, want 0 < goid <= %d", id, max)
	}
}

// TestGoIDSquence verifies that goid returns values which could plausibly be
// goroutine IDs. If this test breaks or becomes flaky, the structs in
// goid_unsafe.go may need to be updated.
func TestGoIDSquence(t *testing.T) {
	// Goroutine IDs are cached by each P.
	runtime.GOMAXPROCS(1)

	// Fill any holes in lower range.
	for i := 0; i < 50; i++ {
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			wg.Done()

			// Leak the goroutine to prevent the ID from being
			// reused.
			select {}
		}()
		wg.Wait()
	}

	id := goid()
	for i := 0; i < 100; i++ {
		var (
			newID int64
			wg    sync.WaitGroup
		)
		wg.Add(1)
		go func() {
			newID = goid()
			wg.Done()

			// Leak the goroutine to prevent the ID from being
			// reused.
			select {}
		}()
		wg.Wait()
		if max := id + 100; newID <= id || newID > max {
			t.Errorf("unexpected goroutine ID pattern, got goid = %d, want %d < goid <= %d (previous = %d)", newID, id, max, id)
		}
		id = newID
	}
}
