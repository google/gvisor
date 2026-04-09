// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux
// +build linux

package runsc

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	cgroupsv2 "github.com/containerd/cgroups/v2"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/runtime"
)

// mockPublisher records published events for test assertions.
type mockPublisher struct {
	mu     sync.Mutex
	events []mockEvent
}

type mockEvent struct {
	topic string
	event events.Event
}

func (p *mockPublisher) Publish(_ context.Context, topic string, event events.Event) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, mockEvent{topic: topic, event: event})
	return nil
}

func (p *mockPublisher) Close() error {
	return nil
}

func (p *mockPublisher) eventCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.events)
}

// newTestWatcherV2 creates a watcherV2 with a mock publisher for testing.
// The itemCh is unbuffered so sends block until run() reads, providing
// synchronization without sleeps.
func newTestWatcherV2(pub *mockPublisher) *watcherV2 {
	return &watcherV2{
		itemCh:    make(chan itemV2),
		publisher: pub,
		cgroups:   make(map[string]*cgroupsv2.Manager),
		lastOOM:   make(map[string]uint64),
	}
}

// waitForProcessing sends a sentinel event and blocks until run() accepts it.
// Since the channel is unbuffered and run() processes items sequentially, when
// this returns all prior items have been fully processed.
func waitForProcessing(t *testing.T, w *watcherV2) {
	t.Helper()
	select {
	case w.itemCh <- itemV2{id: "__sentinel__", ev: cgroupsv2.Event{}}:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for run() to accept sentinel")
	}
}

func TestWatcherV2AsyncPublishesNewOOM(t *testing.T) {
	pub := &mockPublisher{}
	w := newTestWatcherV2(pub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)

	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 1}}
	waitForProcessing(t, w)

	if got := pub.eventCount(); got != 1 {
		t.Fatalf("expected 1 published event, got %d", got)
	}
	pub.mu.Lock()
	defer pub.mu.Unlock()
	if pub.events[0].topic != runtime.TaskOOMEventTopic {
		t.Errorf("expected topic %q, got %q", runtime.TaskOOMEventTopic, pub.events[0].topic)
	}
}

func TestWatcherV2AsyncDedupsSameOOMCount(t *testing.T) {
	pub := &mockPublisher{}
	w := newTestWatcherV2(pub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)

	// First event should publish.
	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 1}}
	waitForProcessing(t, w)

	// Same OOM count should NOT publish again.
	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 1}}
	waitForProcessing(t, w)

	if got := pub.eventCount(); got != 1 {
		t.Errorf("expected 1 event (dedup), got %d", got)
	}
}

func TestWatcherV2AsyncPublishesIncrementedOOMCount(t *testing.T) {
	pub := &mockPublisher{}
	w := newTestWatcherV2(pub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)

	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 1}}
	waitForProcessing(t, w)

	// New OOM (incremented count) should publish.
	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 2}}
	waitForProcessing(t, w)

	if got := pub.eventCount(); got != 2 {
		t.Errorf("expected 2 events, got %d", got)
	}
}

// TestWatcherV2SyncPreemptsAsync verifies that when the sync path (isOOM)
// claims the publish right first by setting lastOOM, the async path
// (EventChan -> run) is suppressed. This is the core fix for the aarch64
// race: isOOM fires at container exit before the async notification arrives.
//
// Before the fix, lastOOMMap was local to run() and could not be shared
// with any sync path — this test would have been impossible to write.
func TestWatcherV2SyncPreemptsAsync(t *testing.T) {
	pub := &mockPublisher{}
	w := newTestWatcherV2(pub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)

	// Simulate sync path (isOOM) claiming the publish right.
	w.mu.Lock()
	w.lastOOM["c1"] = 1
	w.mu.Unlock()

	// Async event arrives after — should be suppressed.
	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 1}}
	waitForProcessing(t, w)

	if got := pub.eventCount(); got != 0 {
		t.Errorf("expected 0 events (sync preempted async), got %d", got)
	}
}

// TestWatcherV2AsyncPreemptsSync verifies that when the async path publishes
// first, the sync path sees lastOOM already set and returns false. This
// prevents duplicate events on architectures where the async notification
// arrives before container exit (e.g., x86_64).
func TestWatcherV2AsyncPreemptsSync(t *testing.T) {
	pub := &mockPublisher{}
	w := newTestWatcherV2(pub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)

	// Async publishes first.
	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 1}}
	waitForProcessing(t, w)

	if got := pub.eventCount(); got != 1 {
		t.Fatalf("expected async to publish 1 event, got %d", got)
	}

	// Verify lastOOM was updated so sync path would see it.
	w.mu.Lock()
	lastOOM := w.lastOOM["c1"]
	w.mu.Unlock()
	if lastOOM != 1 {
		t.Errorf("expected lastOOM=1 after async publish, got %d", lastOOM)
	}
	// At this point, isOOM would check: stats.MemoryEvents.OomKill(=1) > lastOOM(=1)
	// which is false, so it would return false — no duplicate.
}

// TestWatcherV2ErrorClearsLastOOM verifies that an error from EventChan
// clears the lastOOM entry, so future OOM events are not suppressed.
func TestWatcherV2ErrorClearsLastOOM(t *testing.T) {
	pub := &mockPublisher{}
	w := newTestWatcherV2(pub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)

	// Pre-set lastOOM.
	w.mu.Lock()
	w.lastOOM["c1"] = 1
	w.mu.Unlock()

	// Error event should clear lastOOM.
	w.itemCh <- itemV2{id: "c1", err: fmt.Errorf("cgroup deleted")}
	waitForProcessing(t, w)

	w.mu.Lock()
	_, exists := w.lastOOM["c1"]
	w.mu.Unlock()
	if exists {
		t.Error("expected lastOOM entry to be cleared after error")
	}
}
