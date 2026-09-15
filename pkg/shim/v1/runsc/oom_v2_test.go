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

	cgroupsv2 "github.com/containerd/cgroups/v3/cgroup2"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/core/runtime"
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
// synchronization without sleeps. The stat functions fail by default; tests
// exercising checkOOM override them.
func newTestWatcherV2(pub *mockPublisher) *watcherV2 {
	return &watcherV2{
		itemCh:    make(chan itemV2),
		publisher: pub,
		cgroups:   make(map[string]*cgroupV2Entry),
		lastOOM:   make(map[string]uint64),
		statCgroup: func(*cgroupsv2.Manager) (uint64, error) {
			return 0, fmt.Errorf("statCgroup not configured in test")
		},
		statPath: func(string) (uint64, error) {
			return 0, fmt.Errorf("statPath not configured in test")
		},
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

// TestWatcherV2SyncPreemptsAsync verifies that when the sync path (checkOOM)
// claims the publish right first by setting lastOOM, the async path
// (EventChan -> run) is suppressed. This is the core fix for the aarch64
// race: checkOOM fires at container exit before the async notification arrives.
//
// Before the fix, lastOOMMap was local to run() and could not be shared
// with any sync path — this test would have been impossible to write.
func TestWatcherV2SyncPreemptsAsync(t *testing.T) {
	pub := &mockPublisher{}
	w := newTestWatcherV2(pub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)

	// Simulate sync path (checkOOM) claiming the publish right.
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
	// At this point, checkOOM would check: stats.MemoryEvents.OomKill(=1) > lastOOM(=1)
	// which is false, so it would return false — no duplicate.
}

// TestWatcherV2ErrorRetainsStateForExitCheck verifies that an error from
// EventChan (which fires when the cgroup is deleted — under the systemd
// cgroup driver, the moment the container's process dies) does NOT clear the
// watcher state. checkOOM still needs the cgroups entry to check the parent
// cgroup at exit time, and the lastOOM entry to dedup against events the
// async path already published.
func TestWatcherV2ErrorRetainsStateForExitCheck(t *testing.T) {
	pub := &mockPublisher{}
	w := newTestWatcherV2(pub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)

	w.mu.Lock()
	w.lastOOM["c1"] = 1
	w.cgroups["c1"] = &cgroupV2Entry{parentPath: "/parent", parentBase: 0}
	w.mu.Unlock()

	w.itemCh <- itemV2{id: "c1", err: fmt.Errorf("cgroup deleted")}
	waitForProcessing(t, w)

	w.mu.Lock()
	_, lastOOMExists := w.lastOOM["c1"]
	_, entryExists := w.cgroups["c1"]
	w.mu.Unlock()
	if !lastOOMExists {
		t.Error("expected lastOOM entry to survive EventChan error")
	}
	if !entryExists {
		t.Error("expected cgroups entry to survive EventChan error")
	}
}

// TestWatcherV2CheckOOMScopeGone exercises the systemd-cgroup fallback: the
// container's own cgroup is already removed at exit time, so checkOOM reads the
// parent cgroup's hierarchical oom_kill counter instead, attributing only
// kills recorded since the container was added.
func TestWatcherV2CheckOOMScopeGone(t *testing.T) {
	for _, tc := range []struct {
		name       string
		parentPath string
		parentErr  bool
		parentBase uint64
		parentKill uint64
		lastOOM    uint64
		want       oomStatus
	}{
		{
			// Every cgroup read failed, but the async path already published
			// a TaskOOM (ledger has a kill): the OOM stands for the exit
			// status; nothing new to announce.
			name:       "ledger-rescue-parent-unreadable",
			parentPath: "/pod",
			parentErr:  true,
			lastOOM:    1,
			want:       oomKilledPublished,
		},
		{
			// No parent baseline and no readable cgroup, but the ledger has
			// a kill: same rescue.
			name:       "ledger-rescue-no-parent",
			parentPath: "",
			lastOOM:    1,
			want:       oomKilledPublished,
		},
		{
			// Kill recorded after add: attribute and announce it.
			name:       "oom-since-add",
			parentPath: "/pod",
			parentBase: 2,
			parentKill: 3,
			want:       oomKilledUnpublished,
		},
		{
			// Parent count unchanged since add: no OOM.
			name:       "no-oom-since-add",
			parentPath: "/pod",
			parentBase: 2,
			parentKill: 2,
		},
		{
			// Async path already published this kill: the OOM still stands
			// (drives the 137 exit status), but no duplicate TaskOOM.
			name:       "async-already-published",
			parentPath: "/pod",
			parentBase: 2,
			parentKill: 3,
			lastOOM:    1,
			want:       oomKilledPublished,
		},
		{
			// No parent baseline captured at add: fallback disabled.
			name:       "no-parent",
			parentPath: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newTestWatcherV2(&mockPublisher{})
			w.statCgroup = func(*cgroupsv2.Manager) (uint64, error) {
				return 0, fmt.Errorf("no such file or directory")
			}
			w.statPath = func(p string) (uint64, error) {
				if p != tc.parentPath {
					t.Errorf("statPath(%q), want %q", p, tc.parentPath)
				}
				if tc.parentErr {
					return 0, fmt.Errorf("no such file or directory")
				}
				return tc.parentKill, nil
			}
			w.mu.Lock()
			w.cgroups["c1"] = &cgroupV2Entry{
				parentPath: tc.parentPath,
				parentBase: tc.parentBase,
			}
			if tc.lastOOM != 0 {
				w.lastOOM["c1"] = tc.lastOOM
			}
			w.mu.Unlock()

			if got := w.checkOOM("c1"); got != tc.want {
				t.Errorf("checkOOM() = %v, want %v", got, tc.want)
			}
			w.mu.Lock()
			_, exists := w.cgroups["c1"]
			w.mu.Unlock()
			if exists {
				t.Error("expected checkOOM to consume the cgroups entry")
			}
		})
	}
}

// TestWatcherV2CheckOOMLedgerFastPath verifies that when the async path already
// recorded a kill, checkOOM answers from the shim's own state without touching
// the filesystem at all — internal data structures are consulted before
// files that other actors (systemd) can mutate or remove.
func TestWatcherV2CheckOOMLedgerFastPath(t *testing.T) {
	w := newTestWatcherV2(&mockPublisher{})
	w.statCgroup = func(*cgroupsv2.Manager) (uint64, error) {
		t.Error("statCgroup must not be called when the ledger has a kill")
		return 0, nil
	}
	w.statPath = func(string) (uint64, error) {
		t.Error("statPath must not be called when the ledger has a kill")
		return 0, nil
	}
	w.mu.Lock()
	w.cgroups["c1"] = &cgroupV2Entry{parentPath: "/pod"}
	w.lastOOM["c1"] = 1
	w.mu.Unlock()

	if got := w.checkOOM("c1"); got != oomKilledPublished {
		t.Errorf("checkOOM() = %v, want %v", got, oomKilledPublished)
	}
	w.mu.Lock()
	_, exists := w.cgroups["c1"]
	w.mu.Unlock()
	if exists {
		t.Error("expected checkOOM to consume the cgroups entry")
	}
}

// TestWatcherV2CheckOOMScopeAlive verifies the primary path is unchanged: when
// the container's cgroup is still readable at exit time, its own oom_kill
// count decides, and the parent is not consulted.
func TestWatcherV2CheckOOMScopeAlive(t *testing.T) {
	w := newTestWatcherV2(&mockPublisher{})
	w.statCgroup = func(*cgroupsv2.Manager) (uint64, error) { return 1, nil }
	w.statPath = func(string) (uint64, error) {
		t.Error("parent must not be consulted when the scope stat succeeds")
		return 0, nil
	}
	w.mu.Lock()
	w.cgroups["c1"] = &cgroupV2Entry{parentPath: "/pod"}
	w.mu.Unlock()

	if got := w.checkOOM("c1"); got != oomKilledUnpublished {
		t.Errorf("checkOOM() = %v, want %v", got, oomKilledUnpublished)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if got := w.lastOOM["c1"]; got != 1 {
		t.Errorf("lastOOM = %d, want 1", got)
	}
}

// TestWatcherV2Remove verifies that poller state is reclaimed when containerd
// deletes the container. checkOOM consumes the cgroups entry at exit, but the
// lastOOM ledger deliberately outlives it, so remove is what frees it.
func TestWatcherV2Remove(t *testing.T) {
	w := newTestWatcherV2(&mockPublisher{})
	w.mu.Lock()
	w.cgroups["c1"] = &cgroupV2Entry{parentPath: "/pod"}
	w.lastOOM["c1"] = 1
	w.mu.Unlock()

	w.remove("c1")

	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.cgroups["c1"]; ok {
		t.Error("remove left a cgroups entry behind")
	}
	if _, ok := w.lastOOM["c1"]; ok {
		t.Error("remove left a lastOOM entry behind")
	}
}
