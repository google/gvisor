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

func (p *mockPublisher) Close() error { return nil }

func (p *mockPublisher) eventCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.events)
}

func newTestWatcher(pub *mockPublisher) *watcherV2 {
	return &watcherV2{
		itemCh:    make(chan itemV2),
		publisher: pub,
		hasOOM:    make(map[string]bool),
	}
}

// drain sends a sentinel and blocks until run() processes it.
func drain(t *testing.T, w *watcherV2) {
	t.Helper()
	select {
	case w.itemCh <- itemV2{id: "_sentinel_"}:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for run()")
	}
}

// --- Async path tests (run goroutine) ---

func TestAsyncPublishesOOM(t *testing.T) {
	pub := &mockPublisher{}
	w := newTestWatcher(pub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)

	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 1}}
	drain(t, w)

	if got := pub.eventCount(); got != 1 {
		t.Fatalf("want 1 event, got %d", got)
	}
	if pub.events[0].topic != runtime.TaskOOMEventTopic {
		t.Errorf("want topic %q, got %q", runtime.TaskOOMEventTopic, pub.events[0].topic)
	}
}

func TestAsyncDedupsSameCount(t *testing.T) {
	pub := &mockPublisher{}
	w := newTestWatcher(pub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)

	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 1}}
	drain(t, w)
	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 1}}
	drain(t, w)

	if got := pub.eventCount(); got != 1 {
		t.Errorf("want 1 event (dedup), got %d", got)
	}
}

func TestAsyncPublishesIncrement(t *testing.T) {
	pub := &mockPublisher{}
	w := newTestWatcher(pub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)

	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 1}}
	drain(t, w)
	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 2}}
	drain(t, w)

	if got := pub.eventCount(); got != 2 {
		t.Errorf("want 2 events, got %d", got)
	}
}

func TestAsyncIgnoresErrors(t *testing.T) {
	pub := &mockPublisher{}
	w := newTestWatcher(pub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)

	w.itemCh <- itemV2{id: "c1", err: fmt.Errorf("cgroup deleted")}
	drain(t, w)

	if got := pub.eventCount(); got != 0 {
		t.Errorf("want 0 events after error, got %d", got)
	}
}

// --- Sync path tests (isOOM at container exit) ---

func TestIsOOMNoEvent(t *testing.T) {
	w := newTestWatcher(&mockPublisher{})
	if w.isOOM("c1") {
		t.Error("isOOM should be false with no events")
	}
}

func TestIsOOMAfterEagerSet(t *testing.T) {
	w := newTestWatcher(&mockPublisher{})
	// Simulate EventChan goroutine setting hasOOM eagerly.
	w.mu.Lock()
	w.hasOOM["c1"] = true
	w.mu.Unlock()

	if !w.isOOM("c1") {
		t.Error("isOOM should be true after OOM was observed")
	}
	// Consumed — second call returns false.
	if w.isOOM("c1") {
		t.Error("isOOM should be false after consumption")
	}
}

// TestIsOOMRace is the core aarch64 regression test.
//
// Scenario: EventChan goroutine set hasOOM (it read memory.events while
// the cgroup was alive), but run() hasn't processed the event yet.
// Then an error arrives (systemd deleted the cgroup). isOOM() must still
// return true because hasOOM was set before the error.
func TestIsOOMRace(t *testing.T) {
	pub := &mockPublisher{}
	w := newTestWatcher(pub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)

	// Step 1: EventChan goroutine saw OOM.
	w.mu.Lock()
	w.hasOOM["c1"] = true
	w.mu.Unlock()

	// Step 2: Error arrives (cgroup deleted by systemd).
	w.itemCh <- itemV2{id: "c1", err: fmt.Errorf("cgroup deleted")}
	drain(t, w)

	// Step 3: checkProcesses calls isOOM. Must return true.
	if !w.isOOM("c1") {
		t.Error("isOOM should be true — OOM was seen before cgroup deletion")
	}
}
