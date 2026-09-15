// Copyright The containerd Authors.
// Copyright 2021 The gVisor Authors.
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
	"path"
	"sync"

	cgroupsv2 "github.com/containerd/cgroups/v3/cgroup2"
	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/containerd/v2/pkg/shim"
	"github.com/sirupsen/logrus"
)

// newOOMv2Epoller returns an implementation that listens to OOM events
// from a container's cgroups v2.  This is copied from containerd to avoid
// having to upgrade containerd package just to get it
func newOOMv2Poller(publisher shim.Publisher) (oomPoller, error) {
	return &watcherV2{
		itemCh:     make(chan itemV2),
		publisher:  publisher,
		cgroups:    make(map[string]*cgroupV2Entry),
		lastOOM:    make(map[string]uint64),
		statCgroup: statCgroupOOMKill,
		statPath:   statPathOOMKill,
	}, nil
}

// cgroupV2 bundles a loaded v2 cgroup manager with its unified group path.
// The manager does not expose its path, and the OOM poller needs the path to
// locate the cgroup's parent.
type cgroupV2 struct {
	mgr  *cgroupsv2.Manager
	path string
}

// cgroupV2Entry is the per-container state the poller needs to check for OOM
// kills when the container exits.
type cgroupV2Entry struct {
	mgr *cgroupsv2.Manager
	// parentPath is the unified group path of the container cgroup's parent
	// (the pod slice under Kubernetes). It is consulted when the container's
	// own cgroup is already gone at exit time. Empty if the parent could not
	// be read when the container was added, which disables the fallback.
	parentPath string
	// parentBase is the parent's oom_kill count when the container was
	// added. Kills recorded before that must not be attributed to this
	// container.
	parentBase uint64
}

// watcher implementation for handling OOM events from a container's cgroup
type watcherV2 struct {
	itemCh    chan itemV2
	publisher shim.Publisher

	// statCgroup reads the oom_kill count from a loaded cgroup, and statPath
	// reads it for the cgroup at a unified group path. They are fields so
	// tests can substitute counts and failures.
	statCgroup func(*cgroupsv2.Manager) (uint64, error)
	statPath   func(string) (uint64, error)

	mu sync.Mutex

	// +checklocks:mu
	cgroups map[string]*cgroupV2Entry

	// lastOOM tracks the last claimed OOM kill count per container.
	// The async (EventChan) and sync (checkOOM) paths claim counts before
	// publishing to prevent duplicate TaskOOM events. A claim does not
	// imply that publication has finished.
	//
	// +checklocks:mu
	lastOOM map[string]uint64
}

// statCgroupOOMKill returns the oom_kill count from the cgroup's
// memory.events.
func statCgroupOOMKill(mgr *cgroupsv2.Manager) (uint64, error) {
	stats, err := mgr.Stat()
	if err != nil {
		return 0, err
	}
	if stats.MemoryEvents == nil {
		return 0, nil
	}
	return stats.MemoryEvents.OomKill, nil
}

// statPathOOMKill returns the oom_kill count of the cgroup at the given
// unified group path.
func statPathOOMKill(groupPath string) (uint64, error) {
	mgr, err := cgroupsv2.Load(groupPath)
	if err != nil {
		return 0, err
	}
	return statCgroupOOMKill(mgr)
}

type itemV2 struct {
	id  string
	ev  cgroupsv2.Event
	err error
}

// Close closes the watcher
func (w *watcherV2) Close() error {
	return nil
}

// Run the loop
func (w *watcherV2) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			w.Close()
			return
		case i := <-w.itemCh:
			if i.err != nil {
				// Keep w.cgroups and w.lastOOM: the sync OOM checker
				// (checkOOM) needs them to determine whether the container
				// was OOM-killed when systemd has already removed its cgroup
				// files.
				logrus.WithError(i.err).Debugf("Error listening for OOM, id: %q", i.id)
				continue
			}
			logrus.Debugf("Received OOM event, id: %q, event: %+v", i.id, i.ev)
			w.mu.Lock()
			lastOOM := w.lastOOM[i.id]
			shouldPublish := i.ev.OOMKill > lastOOM
			if shouldPublish {
				w.lastOOM[i.id] = i.ev.OOMKill
			}
			w.mu.Unlock()
			if shouldPublish {
				if err := w.publisher.Publish(ctx, runtime.TaskOOMEventTopic, &TaskOOM{
					ContainerID: i.id,
				}); err != nil {
					logrus.WithError(err).Error("Publish OOM event")
				}
			}
		}
	}
}

// checkOOM synchronously checks if the container was OOM-killed, consulting
// in order: the shared lastOOM ledger (what the async path already recorded),
// the container cgroup's memory.events, and the parent cgroup's count
// relative to the baseline captured at add. Called at container exit so the
// verdict does not depend on the async EventChan winning the race against
// exit processing (which it loses on some architectures, notably aarch64).
//
// +checklocksexclude:w.mu
func (w *watcherV2) checkOOM(id string) oomStatus {
	w.mu.Lock()
	entry, ok := w.cgroups[id]
	if ok {
		delete(w.cgroups, id)
	}
	w.mu.Unlock()
	if !ok {
		return oomNotKilled
	}
	// Check internal state before host files: systemd removes the scope
	// cgroup the moment its process dies, but nothing can remove the ledger.
	w.mu.Lock()
	recorded := w.lastOOM[id]
	w.mu.Unlock()
	if recorded > 0 {
		return oomKilledPublished
	}
	// Nothing recorded — the async notification may not have arrived yet.
	// Read the kernel's counters, which are written at kill time, before
	// this exit could run.
	var oomKill uint64
	if count, err := w.statCgroup(entry.mgr); err == nil {
		oomKill = count
	} else if entry.parentPath != "" {
		// Scope already removed (systemd cgroup driver). The pod slice
		// outlives it, and its memory.events is hierarchical (Linux 5.2+),
		// so it still counts kills from the removed scope. The baseline
		// from add() keeps earlier kills in the pod from being
		// misattributed.
		if parentKill, perr := w.statPath(entry.parentPath); perr != nil {
			logrus.WithError(perr).Warnf("Failed to stat cgroup and parent %q for OOM check, id: %q", entry.parentPath, id)
		} else if parentKill > entry.parentBase {
			oomKill = parentKill - entry.parentBase
		}
	} else {
		logrus.WithError(err).Warnf("Failed to stat cgroup for OOM check and no parent to fall back to, id: %q", id)
	}
	// Claim the publish right under the lock, re-reading the ledger in case
	// the async path claimed this OOM count while the reads above were in
	// flight. If it did, skip to avoid duplicate events.
	w.mu.Lock()
	lastOOM := w.lastOOM[id]
	publish := oomKill > lastOOM
	if publish {
		w.lastOOM[id] = oomKill
	}
	w.mu.Unlock()
	switch {
	case publish:
		return oomKilledUnpublished
	case oomKill > 0 || lastOOM > 0:
		return oomKilledPublished
	default:
		return oomNotKilled
	}
}

// remove drops the container's poller state. checkOOM consumes the cgroups
// entry at exit, but the lastOOM ledger has to outlive that check so an async
// event still in flight cannot republish TaskOOM; it is reclaimed here, once
// containerd is done with the container.
func (w *watcherV2) remove(id string) {
	w.mu.Lock()
	delete(w.cgroups, id)
	delete(w.lastOOM, id)
	w.mu.Unlock()
}

// Add cgroups.Cgroup to the epoll monitor
//
// +checklocksexclude:w.mu
func (w *watcherV2) add(id string, cgx any) error {
	cg, ok := cgx.(*cgroupV2)
	if !ok {
		return fmt.Errorf("expected *cgroupV2, got: %T", cgx)
	}
	entry := &cgroupV2Entry{mgr: cg.mgr}
	if parent := path.Dir(cg.path); parent != "/" && parent != "." {
		if base, err := w.statPath(parent); err == nil {
			entry.parentPath = parent
			entry.parentBase = base
		} else {
			// entry.parentPath stays empty, which is what makes checkOOM skip
			// the parent fallback: without a baseline it could not tell a kill
			// of this container from one recorded in the pod before it began.
			logrus.WithError(err).Warnf("Failed to read parent cgroup %q; exit-time OOM fallback disabled, id: %q", parent, id)
		}
	}
	w.mu.Lock()
	w.cgroups[id] = entry
	// A reused container id starts fresh: drop dedup state kept for the
	// previous container after its event channel died.
	delete(w.lastOOM, id)
	w.mu.Unlock()
	// NOTE: containerd/cgroups/v2 does not support closing eventCh routine
	// currently. The routine shuts down when an error happens, mostly when the
	// cgroup is deleted.
	eventCh, errCh := cg.mgr.EventChan()
	go func() {
		for {
			i := itemV2{id: id}
			select {
			case ev := <-eventCh:
				i.ev = ev
				w.itemCh <- i
			case err := <-errCh:
				i.err = err
				w.itemCh <- i
				// we no longer get any event/err when we got an err
				logrus.WithError(err).Warn("error from eventChan")
				return
			}
		}
	}()
	return nil
}
