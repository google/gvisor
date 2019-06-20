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

// Package memevent implements the memory usage events controller, which
// periodically emits events via the eventchannel.
package memevent

import (
	"sync"
	"time"

	"gvisor.dev/gvisor/pkg/eventchannel"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/metric"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	pb "gvisor.dev/gvisor/pkg/sentry/kernel/memevent/memory_events_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

var totalTicks = metric.MustCreateNewUint64Metric("/memory_events/ticks", false /*sync*/, "Total number of memory event periods that have elapsed since startup.")
var totalEvents = metric.MustCreateNewUint64Metric("/memory_events/events", false /*sync*/, "Total number of memory events emitted.")

// MemoryEvents describes the configuration for the global memory event emitter.
type MemoryEvents struct {
	k *kernel.Kernel

	// The period is how often to emit an event. The memory events goroutine
	// will ensure a minimum of one event is emitted per this period, regardless
	// how of much memory usage has changed.
	period time.Duration

	// Writing to this channel indicates the memory goroutine should stop.
	stop chan struct{}

	// done is used to signal when the memory event goroutine has exited.
	done sync.WaitGroup
}

// New creates a new MemoryEvents.
func New(k *kernel.Kernel, period time.Duration) *MemoryEvents {
	return &MemoryEvents{
		k:      k,
		period: period,
		stop:   make(chan struct{}),
	}
}

// Stop stops the memory usage events emitter goroutine. Stop must not be called
// concurrently with Start and may only be called once.
func (m *MemoryEvents) Stop() {
	close(m.stop)
	m.done.Wait()
}

// Start starts the memory usage events emitter goroutine. Start must not be
// called concurrently with Stop and may only be called once.
func (m *MemoryEvents) Start() {
	if m.period == 0 {
		return
	}
	m.done.Add(1)
	go m.run() // S/R-SAFE: doesn't interact with saved state.
}

func (m *MemoryEvents) run() {
	defer m.done.Done()

	// Emit the first event immediately on startup.
	totalTicks.Increment()
	m.emit()

	ticker := time.NewTicker(m.period)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			totalTicks.Increment()
			m.emit()
		}
	}
}

func (m *MemoryEvents) emit() {
	totalPlatform, err := m.k.MemoryFile().TotalUsage()
	if err != nil {
		log.Warningf("Failed to fetch memory usage for memory events: %v", err)
		return
	}
	snapshot, _ := usage.MemoryAccounting.Copy()
	total := totalPlatform + snapshot.Mapped

	totalEvents.Increment()
	eventchannel.Emit(&pb.MemoryUsageEvent{
		Mapped: snapshot.Mapped,
		Total:  total,
	})
}
