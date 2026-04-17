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
	"sync"

	cgroupsv2 "github.com/containerd/cgroups/v2"
	"github.com/containerd/containerd/runtime"
	"github.com/containerd/containerd/runtime/v2/shim"
	"github.com/sirupsen/logrus"
)

func newOOMv2Poller(publisher shim.Publisher) (oomPoller, error) {
	return &watcherV2{
		itemCh:    make(chan itemV2),
		publisher: publisher,
		hasOOM:    make(map[string]bool),
	}, nil
}

// watcherV2 handles OOM events from a container's cgroups v2.
//
// OOM detection has two paths that coordinate to ensure kubelet sees
// reason=OOMKilled:
//
//   - Async: the EventChan goroutine reads memory.events via inotify and
//     sends events to run(), which publishes TaskOOM directly to containerd.
//     This is the fast path that works well on x86_64.
//
//   - Sync: at container exit, checkProcesses() calls isOOM() which checks
//     whether an OOM was observed. If so, it returns true and the caller
//     publishes TaskOOM via s.send() before TaskExit, guaranteeing order.
//
// On aarch64, the async path loses the race against the container exit
// notification. The sync path provides the fallback. Both paths may publish
// TaskOOM for the same event — this is harmless since kubelet just records
// "OOM happened" as an idempotent flag.
//
// The hasOOM map is the bridge: set eagerly by the EventChan goroutine
// (while the cgroup is still alive), consumed by isOOM() at exit time
// (when the cgroup may already be deleted by systemd).
type watcherV2 struct {
	itemCh    chan itemV2
	publisher shim.Publisher

	mu sync.Mutex
	// hasOOM is set true by the EventChan goroutine when it observes
	// OOMKill > 0 in a cgroup event. Set BEFORE queuing to run() via
	// itemCh, so isOOM() sees it immediately even if run() hasn't
	// processed the event yet.
	hasOOM map[string]bool
}

type itemV2 struct {
	id  string
	ev  cgroupsv2.Event
	err error
}

func (w *watcherV2) Close() error {
	return nil
}

// run processes async OOM events from the EventChan goroutines and publishes
// TaskOOM directly to containerd. This is the fast path for real-time OOM
// notification. Dedup is handled locally (per-goroutine lastOOM map) since
// EventChan can fire multiple times for the same OOM event.
func (w *watcherV2) run(ctx context.Context) {
	lastOOM := make(map[string]uint64)
	for {
		select {
		case <-ctx.Done():
			w.Close()
			return
		case i := <-w.itemCh:
			if i.err != nil {
				logrus.WithError(i.err).Debugf("Error listening for OOM, id: %q", i.id)
				delete(lastOOM, i.id)
				continue
			}
			if i.ev.OOMKill <= lastOOM[i.id] {
				continue
			}
			lastOOM[i.id] = i.ev.OOMKill
			logrus.Debugf("Publishing OOM event, id: %q, oomKill: %d", i.id, i.ev.OOMKill)
			if err := w.publisher.Publish(ctx, runtime.TaskOOMEventTopic, &TaskOOM{
				ContainerID: i.id,
			}); err != nil {
				logrus.WithError(err).Error("Publish OOM event")
			}
		}
	}
}

// isOOM reports whether the container experienced an OOM kill. It checks the
// hasOOM flag set eagerly by the EventChan goroutine while the cgroup was
// still alive. This avoids reading memory.events at exit time, which fails
// on systemd-managed cgroups where the directory is removed before the shim
// processes the exit.
//
// The flag is consumed (deleted) on read — subsequent calls return false.
func (w *watcherV2) isOOM(id string) bool {
	w.mu.Lock()
	oom := w.hasOOM[id]
	delete(w.hasOOM, id)
	w.mu.Unlock()
	return oom
}

// add starts watching a container's cgroup for OOM events.
func (w *watcherV2) add(id string, cgx any) error {
	cg, ok := cgx.(*cgroupsv2.Manager)
	if !ok {
		return fmt.Errorf("expected *cgroupsv2.Manager, got: %T", cgx)
	}
	eventCh, errCh := cg.EventChan()
	go func() {
		for {
			i := itemV2{id: id}
			select {
			case ev := <-eventCh:
				if ev.OOMKill > 0 {
					w.mu.Lock()
					w.hasOOM[id] = true
					w.mu.Unlock()
				}
				i.ev = ev
				w.itemCh <- i
			case err := <-errCh:
				i.err = err
				w.itemCh <- i
				logrus.WithError(err).Warn("error from eventChan")
				return
			}
		}
	}()
	return nil
}
