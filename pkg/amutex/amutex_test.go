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

package amutex

import (
	"sync"
	"testing"
	"time"
)

type sleeper struct {
	ch chan struct{}
}

func (s *sleeper) SleepStart() <-chan struct{} {
	return s.ch
}

func (*sleeper) SleepFinish(bool) {
}

func (s *sleeper) Interrupted() bool {
	return len(s.ch) != 0
}

func TestMutualExclusion(t *testing.T) {
	var m AbortableMutex
	m.Init()

	// Test mutual exclusion by running "gr" goroutines concurrently, and
	// have each one increment a counter "iters" times within the critical
	// section established by the mutex.
	//
	// If at the end of the counter is not gr * iters, then we know that
	// goroutines ran concurrently within the critical section.
	//
	// If one of the goroutines doesn't complete, it's likely a bug that
	// causes to to wait forever.
	const gr = 1000
	const iters = 100000
	v := 0
	var wg sync.WaitGroup
	for i := 0; i < gr; i++ {
		wg.Add(1)
		go func() {
			for j := 0; j < iters; j++ {
				m.Lock(nil)
				v++
				m.Unlock()
			}
			wg.Done()
		}()
	}

	wg.Wait()

	if v != gr*iters {
		t.Fatalf("Bad count: got %v, want %v", v, gr*iters)
	}
}

func TestAbortWait(t *testing.T) {
	var s sleeper
	var m AbortableMutex
	m.Init()

	// Lock the mutex.
	m.Lock(&s)

	// Lock again, but this time cancel after 500ms.
	s.ch = make(chan struct{}, 1)
	go func() {
		time.Sleep(500 * time.Millisecond)
		s.ch <- struct{}{}
	}()
	if v := m.Lock(&s); v {
		t.Fatalf("Lock succeeded when it should have failed")
	}

	// Lock again, but cancel right away.
	s.ch <- struct{}{}
	if v := m.Lock(&s); v {
		t.Fatalf("Lock succeeded when it should have failed")
	}
}
