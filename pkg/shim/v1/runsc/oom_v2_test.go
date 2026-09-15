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
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	cgroupsv2 "github.com/containerd/cgroups/v3/cgroup2"
	"github.com/containerd/containerd/v2/core/events"
	"github.com/containerd/containerd/v2/core/runtime"
	"golang.org/x/sys/unix"
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

// testCgroupPath is the unified group path of the container's own cgroup in
// tests. Its parent, when a test configures one, is "/pod".
const testCgroupPath = "/pod/c1"

// errCgroupGone is what statPath returns for a cgroup systemd has removed.
func errCgroupGone(p string) error {
	return &os.PathError{Op: "open", Path: p, Err: unix.ENOENT}
}

// newTestWatcherV2 creates a watcherV2 with a mock publisher for testing.
// The itemCh is unbuffered so sends block until run() reads, providing
// synchronization without sleeps. statPath fails by default; tests exercising
// isOOM override it.
func newTestWatcherV2(pub *mockPublisher) *watcherV2 {
	return &watcherV2{
		itemCh:    make(chan itemV2),
		publisher: pub,
		cgroups:   make(map[string]*cgroupV2Entry),
		lastOOM:   make(map[string]uint64),
		statPath: func(string) (uint64, error) {
			return 0, fmt.Errorf("statPath not configured in test")
		},
	}
}

// trackContainer marks id as tracked with the given claimed OOM count, as add
// does. Without it the poller treats the container as removed.
func trackContainer(w *watcherV2, id string, count uint64) {
	w.mu.Lock()
	w.lastOOM[id] = count
	w.mu.Unlock()
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

	trackContainer(w, "c1", 0)
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

	trackContainer(w, "c1", 0)
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

	trackContainer(w, "c1", 0)
	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 1}}
	waitForProcessing(t, w)

	// New OOM (incremented count) should publish.
	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 2}}
	waitForProcessing(t, w)

	if got := pub.eventCount(); got != 2 {
		t.Errorf("expected 2 events, got %d", got)
	}
}

// TestWatcherV2ErrorRetainsStateForExitCheck verifies that an error from
// EventChan (which fires when the cgroup is deleted — under the systemd
// cgroup driver, the moment the container's process dies) keeps both the
// cgroups entry and the ledger. isOOM needs the entry to find the pod cgroup,
// and dropping the ledger would make a kill the async path already announced
// look unannounced, producing a second TaskOOM.
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
	defer w.mu.Unlock()
	if _, ok := w.cgroups["c1"]; !ok {
		t.Error("expected cgroups entry to survive EventChan error")
	}
	if got, ok := w.lastOOM["c1"]; !ok || got != 1 {
		t.Errorf("lastOOM = %d (present %v), want 1: dropping it causes a duplicate TaskOOM", got, ok)
	}
}

// TestWatcherV2IsOOMScopeGone exercises the systemd-cgroup fallback: the
// container's own cgroup is already removed at exit time, so isOOM reads the
// parent cgroup's hierarchical oom_kill counter instead, attributing only
// kills recorded since the container was added.
func TestWatcherV2IsOOMScopeGone(t *testing.T) {
	for _, tc := range []struct {
		name       string
		parentPath string
		parentErr  bool
		parentBase uint64
		base       uint64
		parentKill uint64
		lastOOM    uint64
		want       oomStatus
	}{
		{
			// Every cgroup read failed: nothing establishes a kill.
			name:       "parent-unreadable",
			parentPath: "/pod",
			parentErr:  true,
		},
		{
			// Kill recorded after add: attribute it to this container.
			name:       "oom-since-add",
			parentPath: "/pod",
			parentBase: 2,
			parentKill: 3,
			want:       oomKilledUnpublished,
		},
		{
			// Every cgroup read failed, but the async path already announced
			// a kill: it stands for the exit status, with nothing new to say.
			name:       "ledger-rescue-parent-unreadable",
			parentPath: "/pod",
			parentErr:  true,
			lastOOM:    1,
			want:       oomKilledPublished,
		},
		{
			// Async path already announced this kill: still a kill, so the
			// exit status becomes 137, but no duplicate TaskOOM.
			name:       "async-already-published",
			parentPath: "/pod",
			parentBase: 2,
			parentKill: 3,
			lastOOM:    1,
			want:       oomKilledPublished,
		},
		{
			// Added after an earlier kill in the pod, then killed itself:
			// only the kill past the baseline is this container's.
			name:       "oom-since-add-with-baseline",
			parentPath: "/pod",
			base:       1,
			parentBase: 5,
			parentKill: 6,
			lastOOM:    1,
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
			// No parent baseline captured at add: fallback disabled.
			name:       "no-parent",
			parentPath: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newTestWatcherV2(&mockPublisher{})
			w.statPath = func(p string) (uint64, error) {
				switch p {
				case testCgroupPath:
					return 0, errCgroupGone(p)
				case tc.parentPath:
					if tc.parentErr {
						return 0, fmt.Errorf("permission denied")
					}
					return tc.parentKill, nil
				}
				t.Errorf("unexpected statPath(%q)", p)
				return 0, fmt.Errorf("unexpected path %q", p)
			}
			w.mu.Lock()
			w.cgroups["c1"] = &cgroupV2Entry{
				path:       testCgroupPath,
				base:       tc.base,
				parentPath: tc.parentPath,
				parentBase: tc.parentBase,
			}
			w.lastOOM["c1"] = tc.lastOOM
			w.mu.Unlock()

			if got := w.isOOM("c1"); got != tc.want {
				t.Errorf("isOOM() = %v, want %v", got, tc.want)
			}
			w.mu.Lock()
			_, exists := w.cgroups["c1"]
			w.mu.Unlock()
			if exists {
				t.Error("expected isOOM to consume the cgroups entry")
			}
		})
	}
}

// TestWatcherV2IsOOMScopeAlive verifies the primary path is unchanged: when
// the container's cgroup is still readable at exit time, its own oom_kill
// count decides, and the parent is not consulted.
func TestWatcherV2IsOOMScopeAlive(t *testing.T) {
	w := newTestWatcherV2(&mockPublisher{})
	w.statPath = func(p string) (uint64, error) {
		if p != testCgroupPath {
			t.Errorf("parent must not be consulted when the cgroup read succeeds, got statPath(%q)", p)
			return 0, nil
		}
		return 1, nil
	}
	w.mu.Lock()
	w.cgroups["c1"] = &cgroupV2Entry{path: testCgroupPath, parentPath: "/pod"}
	w.lastOOM["c1"] = 0
	w.mu.Unlock()

	if got := w.isOOM("c1"); got != oomKilledUnpublished {
		t.Errorf("isOOM() = %v, want %v", got, oomKilledUnpublished)
	}
}

// TestWatcherV2IsOOMBaseline covers a container added after an earlier kill in
// the same pod. The sandbox cgroup's oom_kill count is cumulative and shared by
// every container in the pod, so a baseline of zero would blame this container
// for a kill that predates it.
func TestWatcherV2IsOOMBaseline(t *testing.T) {
	for _, tc := range []struct {
		name  string
		count uint64
		want  oomStatus
	}{
		{"earlier-kill-is-not-ours", 1, oomNotKilled},
		{"killed-after-add", 2, oomKilledUnpublished},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newTestWatcherV2(&mockPublisher{})
			w.statPath = func(string) (uint64, error) { return tc.count, nil }
			w.mu.Lock()
			// Added when the pod had already recorded one kill.
			w.cgroups["c1"] = &cgroupV2Entry{path: testCgroupPath, base: 1, parentPath: "/pod"}
			w.lastOOM["c1"] = 1
			w.mu.Unlock()

			if got := w.isOOM("c1"); got != tc.want {
				t.Errorf("isOOM() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestWatcherV2IsOOMReadErrorSkipsParent verifies that an error which does
// not mean the cgroup is gone keeps the pod cgroup out of it. The container
// cgroup still exists, so its own count is the only sound answer; the pod
// cgroup's count includes the rest of the pod.
func TestWatcherV2IsOOMReadErrorSkipsParent(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"permission-denied", &os.PathError{Op: "open", Path: testCgroupPath, Err: unix.EACCES}},
		{"io-error", &os.PathError{Op: "read", Path: testCgroupPath, Err: unix.EIO}},
		{"no-oom-kill-entry", fmt.Errorf("no oom_kill entry in %s", testCgroupPath)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newTestWatcherV2(&mockPublisher{})
			w.statPath = func(p string) (uint64, error) {
				if p != testCgroupPath {
					t.Errorf("pod cgroup must not be consulted for a cgroup that is still there, got statPath(%q)", p)
				}
				return 0, tc.err
			}
			w.mu.Lock()
			w.cgroups["c1"] = &cgroupV2Entry{
				path:       testCgroupPath,
				parentPath: "/pod",
				parentBase: 2,
			}
			w.lastOOM["c1"] = 0
			w.mu.Unlock()

			if got := w.isOOM("c1"); got != oomNotKilled {
				t.Errorf("isOOM() = %v, want %v", got, oomNotKilled)
			}
		})
	}
}

// TestParseOOMKill covers the memory.events parsing, which is read directly
// rather than through Manager.Stat.
func TestParseOOMKill(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    uint64
		wantErr bool
	}{
		{"typical", "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n", 1, false},
		{"zero", "low 0\noom_kill 0\n", 0, false},
		{"large", "oom_kill 18446744073709551615\n", 18446744073709551615, false},
		{"missing-entry", "low 0\nhigh 0\n", 0, true},
		{"empty", "", 0, true},
		{"malformed-value", "oom_kill abc\n", 0, true},
		{"extra-fields-skipped", "oom_kill 2 extra\noom_kill 5\n", 5, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseOOMKill(strings.NewReader(tc.content), "memory.events")
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseOOMKill() error = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Errorf("parseOOMKill() = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestCgroupGone verifies which errors are read as the cgroup having been
// removed, which is what arms the pod cgroup fallback.
func TestCgroupGone(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"enoent", &os.PathError{Op: "open", Err: unix.ENOENT}, true},
		{"enodev", &os.PathError{Op: "read", Err: unix.ENODEV}, true},
		{"eacces", &os.PathError{Op: "open", Err: unix.EACCES}, false},
		{"eio", &os.PathError{Op: "read", Err: unix.EIO}, false},
		{"wrapped-enoent", fmt.Errorf("read: %w", unix.ENOENT), true},
		{"plain", fmt.Errorf("malformed"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cgroupGone(tc.err); got != tc.want {
				t.Errorf("cgroupGone(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestWatcherV2IsOOMUntracks verifies that the exit-time check reclaims the
// poller state for the container, both the cgroups entry it consumes and the
// dedup ledger whose absence marks the container untracked.
func TestWatcherV2IsOOMUntracks(t *testing.T) {
	w := newTestWatcherV2(&mockPublisher{})
	w.statPath = func(string) (uint64, error) { return 1, nil }
	w.mu.Lock()
	w.cgroups["c1"] = &cgroupV2Entry{path: testCgroupPath, parentPath: "/pod"}
	w.lastOOM["c1"] = 0
	w.mu.Unlock()

	if got := w.isOOM("c1"); !got.killed() {
		t.Fatalf("isOOM() = %v, want a kill", got)
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if _, ok := w.cgroups["c1"]; ok {
		t.Error("isOOM left a cgroups entry behind")
	}
	if _, ok := w.lastOOM["c1"]; ok {
		t.Error("isOOM left a lastOOM entry behind")
	}
}

// TestWatcherV2NoPublishAfterExit covers a container that has already exited.
// Its EventChan goroutine watches the shared sandbox cgroup, so it outlives
// the container and cannot be stopped; events it relays afterwards must not
// become a TaskOOM for a container that is gone.
func TestWatcherV2NoPublishAfterExit(t *testing.T) {
	pub := &mockPublisher{}
	w := newTestWatcherV2(pub)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.run(ctx)

	w.statPath = func(string) (uint64, error) { return 1, nil }
	w.mu.Lock()
	w.cgroups["c1"] = &cgroupV2Entry{path: testCgroupPath, parentPath: "/pod"}
	w.lastOOM["c1"] = 0
	w.mu.Unlock()

	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 1}}
	waitForProcessing(t, w)
	if got := pub.eventCount(); got != 1 {
		t.Fatalf("published %d events before exit, want 1", got)
	}

	if got := w.isOOM("c1"); !got.killed() {
		t.Fatalf("isOOM() = %v, want a kill", got)
	}

	// A straggler relayed after the container exited. Its count is higher
	// than anything published, so only being untracked keeps it quiet.
	w.itemCh <- itemV2{id: "c1", ev: cgroupsv2.Event{OOMKill: 2}}
	waitForProcessing(t, w)

	if got := pub.eventCount(); got != 1 {
		t.Errorf("published %d events, want 1: TaskOOM republished for an exited container", got)
	}
}
