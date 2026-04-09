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

// newOOMv2Epoller returns an implementation that listens to OOM events
// from a container's cgroups v2.  This is copied from containerd to avoid
// having to upgrade containerd package just to get it
func newOOMv2Poller(publisher shim.Publisher) (oomPoller, error) {
	return &watcherV2{
		itemCh:    make(chan itemV2),
		publisher: publisher,
		cgroups:   make(map[string]*cgroupsv2.Manager),
		lastOOM:   make(map[string]uint64),
	}, nil
}

// watcher implementation for handling OOM events from a container's cgroup
type watcherV2 struct {
	itemCh    chan itemV2
	publisher shim.Publisher

	mu      sync.Mutex
	cgroups map[string]*cgroupsv2.Manager
	// lastOOM tracks the last published OOM kill count per container.
	// Shared between the async (EventChan) and sync (isOOM) paths to
	// prevent duplicate TaskOOM events.
	lastOOM map[string]uint64
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
				w.mu.Lock()
				delete(w.lastOOM, i.id)
				delete(w.cgroups, i.id)
				w.mu.Unlock()
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

// isOOM synchronously checks if the container's cgroup has recorded any OOM
// kills by reading memory.events directly. This avoids relying solely on the
// async inotify-based EventChan, which can lose the race against the container
// exit notification on some architectures (notably aarch64). It coordinates
// with the async path via the shared lastOOM map to prevent duplicate events.
func (w *watcherV2) isOOM(id string) bool {
	w.mu.Lock()
	cg, ok := w.cgroups[id]
	if ok {
		delete(w.cgroups, id)
	}
	w.mu.Unlock()
	if !ok {
		return false
	}
	stats, err := cg.Stat()
	if err != nil {
		logrus.WithError(err).Warnf("Failed to stat cgroup for OOM check, id: %q", id)
		return false
	}
	if stats.MemoryEvents == nil || stats.MemoryEvents.OomKill == 0 {
		return false
	}
	// Claim the publish right under the lock. If the async path already
	// published for this OOM count, skip to avoid duplicate events.
	w.mu.Lock()
	lastOOM := w.lastOOM[id]
	shouldPublish := stats.MemoryEvents.OomKill > lastOOM
	if shouldPublish {
		w.lastOOM[id] = stats.MemoryEvents.OomKill
	}
	w.mu.Unlock()
	return shouldPublish
}

// Add cgroups.Cgroup to the epoll monitor
func (w *watcherV2) add(id string, cgx any) error {
	cg, ok := cgx.(*cgroupsv2.Manager)
	if !ok {
		return fmt.Errorf("expected *cgroupsv2.Manager, got: %T", cgx)
	}
	w.mu.Lock()
	w.cgroups[id] = cg
	w.mu.Unlock()
	// NOTE: containerd/cgroups/v2 does not support closing eventCh routine
	// currently. The routine shuts down when an error happens, mostly when the
	// cgroup is deleted.
	eventCh, errCh := cg.EventChan()
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
