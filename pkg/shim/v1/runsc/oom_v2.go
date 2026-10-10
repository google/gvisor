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
	// path is the sandbox cgroup's unified group path.
	path string
	// base is the sandbox cgroup's oom_kill count when the container was
	// added. The count is cumulative and shared by every container in the
	// pod, so kills recorded before that are not this container's.
	base uint64
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
	// The async (EventChan) path claims counts before publishing to
	// prevent duplicate TaskOOM events. A claim does not imply that
	// publication has finished.
	//
	// Membership marks the container as tracked: add inserts and isOOM
	// deletes at exit, so an id missing here is one the poller has no
	// business publishing for.
	//
	// +checklocks:mu
	lastOOM map[string]uint64
}

// readOOMKill returns the oom_kill count from memory.events for the cgroup at
// the given unified group path.
//
// It reads the one file this check needs. Manager.Stat reads a dozen more, so
// its error does not say whether memory.events in particular is readable, and
// it reports a missing memory.events as a zero count, which is
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
			lastOOM, tracked := w.lastOOM[i.id]
			shouldPublish := tracked && i.ev.OOMKill > lastOOM
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

// isOOM synchronously checks if the container's cgroup has recorded any OOM
// kills by reading memory.events directly. This avoids relying solely on the
// async inotify-based EventChan, which can lose the race against the container
// exit notification on some architectures (notably aarch64).
//
// +checklocksexclude:w.mu
func (w *watcherV2) isOOM(id string) oomStatus {
	w.mu.Lock()
	entry, ok := w.cgroups[id]
	delete(w.cgroups, id)
	// What the async path has already announced. Dropping it also untracks
	// the container: its EventChan goroutine watches the shared sandbox
	// cgroup, so it outlives the container and keeps relaying events that
	// must not be published for it.
	lastOOM := w.lastOOM[id]
	delete(w.lastOOM, id)
	w.mu.Unlock()
	if !ok {
		return oomNotKilled
	}
	switch oomKill, ok := w.countOOMKills(id, entry); {
	case ok && oomKill > lastOOM:
		return oomKilledUnpublished
	case (ok && oomKill > entry.base) || lastOOM > entry.base:
		return oomKilledPublished
	default:
		return oomNotKilled
	}
}

// countOOMKills returns the sandbox cgroup's oom_kill count, read from its own
// memory.events or, once systemd has removed that cgroup, reconstructed from
// the pod cgroup's. The result is on the same scale as base and lastOOM. ok is
// false when no count could be established, which is not the same as zero.
func (w *watcherV2) countOOMKills(id string, entry *cgroupV2Entry) (count uint64, ok bool) {
	oomKill, err := w.statPath(entry.path)
	if err == nil {
		return oomKill, true
	}
	if !cgroupGone(err) {
		// The cgroup is still there, so its own count is the exact answer and
		// the pod cgroup's is not a substitute for it.
		logrus.WithError(err).Warnf("Failed to read OOM kill count for OOM check, id: %q", id)
		return 0, false
	}
	if entry.parentPath == "" {
		logrus.WithError(err).Warnf("Cgroup is gone and no pod cgroup to fall back to for OOM check, id: %q", id)
		return 0, false
	}
	// Under the systemd cgroup driver systemd removes the scope as soon as
	// the process dies. The pod cgroup outlives it, and its memory.events is
	// hierarchical (Linux 5.2+), so it still counts the kill. Kills in the pod
	// since add are kills in the sandbox since add, so adding them to base
	// reconstructs where the sandbox counter would have stood.
	parentKill, err := w.statPath(entry.parentPath)
	if err != nil {
		logrus.WithError(err).Warnf("Failed to read pod cgroup %q OOM kill count for OOM check, id: %q", entry.parentPath, id)
		return 0, false
	}
	if parentKill > entry.parentBase {
		return entry.base + (parentKill - entry.parentBase), true
	}
	return entry.base, true
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
	// count.
	entry := &cgroupV2Entry{path: cg.path}
	if base, err := w.statPath(cg.path); err != nil {
		logrus.WithError(err).Errorf("Failed to read OOM kill count for %q; earlier kills in the pod may be attributed to this container, id: %q", cg.path, id)
	} else {
		entry.base = base
	}
	parent := filepath.Dir(cg.path)
	if !cg.podParent {
		logrus.Debugf("Parent cgroup %q is not the pod cgroup; cannot fall back to it once %q is removed, id: %q", parent, cg.path, id)
	} else if base, err := w.statPath(parent); err != nil {
		logrus.WithError(err).Errorf("Failed to read pod cgroup %q; cannot fall back to it once %q is removed, id: %q", parent, cg.path, id)
	} else {
		entry.parentPath = parent
		entry.parentBase = base
	}
	w.mu.Lock()
	w.cgroups[id] = entry
	// Nothing has been published for this container yet, and the counter it
	// is compared against already stands at base. Membership marks it
	// tracked.
	w.lastOOM[id] = entry.base
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
