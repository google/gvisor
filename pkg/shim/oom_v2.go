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

package shim

import (
	"context"
	"fmt"

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
	}, nil
}

// watcher implementation for handling OOM events from a container's cgroup
type watcherV2 struct {
	itemCh    chan itemV2
	publisher shim.Publisher
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
	lastOOMMap := make(map[string]uint64) // key: id, value: ev.OOM
	for {
		select {
		case <-ctx.Done():
			w.Close()
			return
		case i := <-w.itemCh:
			if i.err != nil {
				delete(lastOOMMap, i.id)
				continue
			}
			lastOOM := lastOOMMap[i.id]
			if i.ev.OOM > lastOOM {
				if err := w.publisher.Publish(ctx, runtime.TaskOOMEventTopic, &TaskOOM{
					ContainerID: i.id,
				}); err != nil {
					logrus.WithError(err).Error("publish OOM event")
				}
			}
			if i.ev.OOM > 0 {
				lastOOMMap[i.id] = i.ev.OOM
			}
		}
	}
}

// Add cgroups.Cgroup to the epoll monitor
func (w *watcherV2) add(id string, cgx interface{}) error {
	cg, ok := cgx.(*cgroupsv2.Manager)
	if !ok {
		return fmt.Errorf("expected *cgroupsv2.Manager, got: %T", cgx)
	}
	// NOTE: containerd/cgroups/v2 does not support closing eventCh routine currently.
	// The routine shuts down when an error happens, mostly when the cgroup is deleted.
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
