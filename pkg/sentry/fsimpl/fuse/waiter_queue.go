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

package fuse

import (
	"sync"
)

// WaiterEntry is the entry of one blocked async requester.
//
// +stateify savable
type WaiterEntry struct {
	waiterEntry

	c chan struct{}
}

func newWaiterEntry() (WaiterEntry, chan struct{}) {
	c := make(chan struct{}, 1)
	return WaiterEntry{c: c}, c
}

// WaiterQueue represents the wait queue where waiters
// are async request senders.
//
// +stateify savable
type WaiterQueue struct {
	list waiterList `state:"zerovalue"`
	mu   sync.Mutex `state:"nosave"`
}

// enqueue one entry.
func (q *WaiterQueue) enqueue(e *WaiterEntry) {
	q.mu.Lock()
	q.list.PushBack(e)
	q.mu.Unlock()
}

// dequeue one entry from the front and notifie its channel.
func (q *WaiterQueue) dequeue() {
	q.mu.Lock()
	if e := q.list.Front(); e != nil {
		select {
		case e.c <- struct{}{}:
		default:
		}
		q.list.Remove(e)
	}
	q.mu.Unlock()
}

// empty returns true if the queue is empty.
func (q *WaiterQueue) empty() bool {
	q.mu.Lock()
	q.mu.Unlock()
	return q.list.Front() == nil
}
