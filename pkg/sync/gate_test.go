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

package sync

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestGateBasic(t *testing.T) {
	var g Gate

	if !g.Enter() {
		t.Fatalf("Enter failed before Close")
	}
	g.Leave()

	g.Close()
	if g.Enter() {
		t.Fatalf("Enter succeeded after Close")
	}
}

func TestGateConcurrent(t *testing.T) {
	// Each call to testGateConcurrentOnce tests behavior around a single call
	// to Gate.Close, so run many short tests to increase the probability of
	// flushing out any issues.
	totalTime := 5 * time.Second
	timePerTest := 20 * time.Millisecond
	numTests := int(totalTime / timePerTest)
	for i := 0; i < numTests; i++ {
		testGateConcurrentOnce(t, timePerTest)
	}
}

func testGateConcurrentOnce(t *testing.T, d time.Duration) {
	const numGoroutines = 1000

	ctx, cancel := context.WithCancel(context.Background())
	var wg WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()

	var g Gate
	closeState := int32(0) // set to 1 before g.Close() and 2 after it returns

	// Start a large number of goroutines that repeatedly attempt to enter the
	// gate and get the expected result.
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ctx.Err() == nil {
				closedBeforeEnter := atomic.LoadInt32(&closeState) == 2
				if g.Enter() {
					closedBeforeLeave := atomic.LoadInt32(&closeState) == 2
					g.Leave()
					if closedBeforeEnter {
						t.Errorf("Enter succeeded after Close")
						return
					}
					if closedBeforeLeave {
						t.Errorf("Close returned before Leave")
						return
					}
				} else {
					if atomic.LoadInt32(&closeState) == 0 {
						t.Errorf("Enter failed before Close")
						return
					}
				}
				// Go does not preempt busy loops until Go 1.14.
				runtime.Gosched()
			}
		}()
	}

	// Allow goroutines to enter the gate successfully for half of the test's
	// duration, then close the gate and allow goroutines to fail to enter the
	// gate for the remaining half.
	time.Sleep(d / 2)
	atomic.StoreInt32(&closeState, 1)
	g.Close()
	atomic.StoreInt32(&closeState, 2)
	time.Sleep(d / 2)
}

func BenchmarkGateEnterLeave(b *testing.B) {
	var g Gate
	for i := 0; i < b.N; i++ {
		g.Enter()
		g.Leave()
	}
}

func BenchmarkGateClose(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var g Gate
		g.Close()
	}
}

func BenchmarkGateEnterLeaveAsyncClose(b *testing.B) {
	for i := 0; i < b.N; i++ {
		var g Gate
		g.Enter()
		go func() {
			g.Leave()
		}()
		g.Close()
	}
}
