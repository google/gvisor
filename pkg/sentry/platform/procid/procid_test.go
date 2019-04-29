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

package procid

import (
	"os"
	"runtime"
	"sync"
	"syscall"
	"testing"
)

// runOnMain is used to send functions to run on the main (initial) thread.
var runOnMain = make(chan func(), 10)

func checkProcid(t *testing.T, start *sync.WaitGroup, done *sync.WaitGroup) {
	defer done.Done()

	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	start.Done()
	start.Wait()

	procID := Current()
	tid := syscall.Gettid()

	if procID != uint64(tid) {
		t.Logf("Bad procid: expected %v, got %v", tid, procID)
		t.Fail()
	}
}

func TestProcidInitialized(t *testing.T) {
	var start sync.WaitGroup
	var done sync.WaitGroup

	count := 100
	start.Add(count + 1)
	done.Add(count + 1)

	// Run the check on the main thread.
	//
	// When cgo is not included, the only case when procid isn't initialized
	// is in the main (initial) thread, so we have to test this case
	// specifically.
	runOnMain <- func() {
		checkProcid(t, &start, &done)
	}

	// Run the check on a number of different threads.
	for i := 0; i < count; i++ {
		go checkProcid(t, &start, &done)
	}

	done.Wait()
}

func TestMain(m *testing.M) {
	// Make sure we remain at the main (initial) thread.
	runtime.LockOSThread()

	// Start running tests in a different goroutine.
	go func() {
		os.Exit(m.Run())
	}()

	// Execute any functions that have been sent for execution in the main
	// thread.
	for f := range runOnMain {
		f()
	}
}
