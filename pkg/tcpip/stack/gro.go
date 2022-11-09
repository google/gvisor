// Copyright 2022 The gVisor Authors.
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

package stack

import (
	"time"

	"gvisor.dev/gvisor/pkg/atomicbitops"
)

// groDispatcher coalesces incoming TCP4 packets to increase throughput.
type groDispatcher struct {
	// newInterval notifies about changes to the interval.
	newInterval chan struct{}
	// intervalNS is the interval in nanoseconds.
	intervalNS atomicbitops.Int64
	// stop instructs the GRO dispatcher goroutine to stop.
	stop chan struct{}
}

func (gd *groDispatcher) init(interval time.Duration) {
	gd.intervalNS.Store(interval.Nanoseconds())
	gd.newInterval = make(chan struct{}, 1)
	gd.stop = make(chan struct{})
	gd.start(interval)
}

// start spawns a goroutine that flushes the GRO periodically based on the
// interval.
func (gd *groDispatcher) start(interval time.Duration) {
	go func(interval time.Duration) {
		var ch <-chan time.Time
		if interval == 0 {
			// Never run.
			ch = make(<-chan time.Time)
		} else {
			ticker := time.NewTicker(interval)
			ch = ticker.C
		}
		for {
			select {
			case <-gd.newInterval:
				interval = time.Duration(gd.intervalNS.Load()) * time.Nanosecond
				if interval == 0 {
					// Never run.
					ch = make(<-chan time.Time)
				} else {
					ticker := time.NewTicker(interval)
					ch = ticker.C
				}
			case <-ch:
				gd.flush()
			case <-gd.stop:
				return
			}
		}
	}(interval)
}

func (gd *groDispatcher) getInterval() time.Duration {
	return time.Duration(gd.intervalNS.Load()) * time.Nanosecond
}

func (gd *groDispatcher) setInterval(interval time.Duration) {
	gd.intervalNS.Store(interval.Nanoseconds())
	gd.newInterval <- struct{}{}
}

func (gd *groDispatcher) dispatch(pkt PacketBufferPtr, ep NetworkEndpoint) {
	// Just pass up the stack for now.
	ep.HandlePacket(pkt)
}

// flush sends any packets older than interval up the stack.
func (gd *groDispatcher) flush() {
	// No-op for now.
}

// close stops the GRO goroutine.
func (gd *groDispatcher) close() {
	// TODO(b/256037250): DecRef any packets stored in GRO.
	gd.stop <- struct{}{}
}
