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
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	cgroupsv2 "github.com/containerd/cgroups/v3/cgroup2"
	"github.com/containerd/containerd/v2/core/runtime"
	"github.com/containerd/containerd/v2/pkg/shim"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

// unifiedMountpoint is where the cgroup v2 hierarchy is mounted. The cgroups
// package hardcodes the same path when loading a group by path.
const unifiedMountpoint = "/sys/fs/cgroup"

// newOOMv2Epoller returns an implementation that listens to OOM events
// from a container's cgroups v2.  This is copied from containerd to avoid
// having to upgrade containerd package just to get it
func newOOMv2Poller(publisher shim.Publisher) (oomPoller, error) {
	return &watcherV2{
		itemCh:    make(chan itemV2),
		publisher: publisher,
		cgroups:   make(map[string]*cgroupV2Entry),
		lastOOM:   make(map[string]uint64),
		statPath:  readOOMKill,
	}, nil
}

// cgroupV2 bundles a loaded v2 cgroup manager with its unified group path.
// The manager does not expose its path, and the OOM poller needs the path to
// locate the cgroup's parent.
type cgroupV2 struct {
	mgr  *cgroupsv2.Manager
	path string
	// podParent is set when the cgroup's parent is the pod cgroup, the only
	// case where the parent can stand in for this cgroup once it is removed.
	// See hasPodCgroupParent.
	podParent bool
}

// cgroupV2Entry is the per-container state the poller needs to check for OOM
// kills when the container exits.
type cgroupV2Entry struct {
	// path is the container cgroup's unified group path.
	path string
	// parentPath is the unified group path of the pod cgroup. It is consulted
	// when the container's own cgroup is already gone at exit time. Empty
	// when the parent is not the pod cgroup or could not be read at add time,
	// which disables the fallback.
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

	// statPath reads the oom_kill count for the cgroup at a unified group
	// path. It is a field so tests can substitute counts and failures.
	statPath func(string) (uint64, error)

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

// readOOMKill returns the oom_kill count from memory.events for the cgroup at
// the given unified group path.
//
// It reads the one file the OOM check needs. Manager.Stat reads a dozen more,
// so its error does not say whether memory.events in particular is readable,
// and it reports a missing memory.events as a zero count, which is
// indistinguishable from "not OOM-killed".
func readOOMKill(groupPath string) (uint64, error) {
	name := filepath.Join(unifiedMountpoint, groupPath, "memory.events")
	f, err := os.Open(name)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return parseOOMKill(f, name)
}

// parseOOMKill extracts the oom_kill counter from the contents of a
// memory.events file. name is used for error messages only.
func parseOOMKill(r io.Reader, name string) (uint64, error) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || fields[0] != "oom_kill" {
			continue
		}
		count, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parse oom_kill in %s: %w", name, err)
		}
		return count, nil
	}
	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("read %s: %w", name, err)
	}
	return 0, fmt.Errorf("no oom_kill entry in %s", name)
}

// cgroupGone reports whether err means the cgroup no longer exists. The kernel
// reports ENOENT once the directory is gone, and ENODEV when it is removed
// between the open and the read.
func cgroupGone(err error) bool {
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENODEV)
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
	count, err := w.statPath(entry.path)
	switch {
	case err == nil:
		oomKill = count
	case !cgroupGone(err):
		// The cgroup is still there, so its own count is the exact answer
		// and the parent's is not a substitute for it.
		logrus.WithError(err).Warnf("Failed to read OOM kill count for OOM check, id: %q", id)
	case entry.parentPath == "":
		logrus.WithError(err).Warnf("Cgroup is gone and no parent to fall back to for OOM check, id: %q", id)
	default:
		// Scope already removed (systemd cgroup driver). The pod cgroup
		// outlives it, and its memory.events is hierarchical (Linux 5.2+),
		// so it still counts kills from the removed scope. The baseline
		// from add() keeps earlier kills in the pod from being
		// misattributed.
		if parentKill, perr := w.statPath(entry.parentPath); perr != nil {
			logrus.WithError(perr).Warnf("Failed to read parent %q OOM kill count for OOM check, id: %q", entry.parentPath, id)
		} else if parentKill > entry.parentBase {
			oomKill = parentKill - entry.parentBase
		}
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
	// Arm the exit-time fallback by recording the pod cgroup and its current
	// count. Leaving parentPath empty is what makes checkOOM skip the
	// fallback: without a baseline it could not tell a kill of this container
	// from one recorded in the pod before it began.
	entry := &cgroupV2Entry{path: cg.path}
	parent := filepath.Dir(cg.path)
	if !cg.podParent {
		logrus.Errorf("Parent cgroup %q is not the pod cgroup; cannot fall back to it once %q is removed, id: %q", parent, cg.path, id)
	} else if base, err := w.statPath(parent); err != nil {
		logrus.WithError(err).Errorf("Failed to read pod cgroup %q; cannot fall back to it once %q is removed, id: %q", parent, cg.path, id)
	} else {
		entry.parentPath = parent
		entry.parentBase = base
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
