// Copyright 2018 The containerd Authors.
// Copyright 2018 The gVisor Authors.
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
	"sync"

	"github.com/containerd/cgroups"
	"github.com/containerd/containerd/events"
	"github.com/containerd/containerd/runtime"
	"golang.org/x/sys/unix"
)

func newOOMEpoller(publisher events.Publisher) (*epoller, error) {
	fd, err := unix.EpollCreate1(unix.EPOLL_CLOEXEC)
	if err != nil {
		return nil, err
	}
	return &epoller{
		fd:        fd,
		publisher: publisher,
		set:       make(map[uintptr]*item),
	}, nil
}

type epoller struct {
	mu sync.Mutex

	fd        int
	publisher events.Publisher
	set       map[uintptr]*item
}

type item struct {
	id string
	cg cgroups.Cgroup
}

func (e *epoller) Close() error {
	return unix.Close(e.fd)
}

func (e *epoller) run(ctx context.Context) {
	var events [128]unix.EpollEvent
	for {
		select {
		case <-ctx.Done():
			e.Close()
			return
		default:
			n, err := unix.EpollWait(e.fd, events[:], -1)
			if err != nil {
				if err == unix.EINTR || err == unix.EAGAIN {
					continue
				}
				// Should not happen.
				panic(fmt.Errorf("cgroups: epoll wait: %w", err))
			}
			for i := 0; i < n; i++ {
				e.process(ctx, uintptr(events[i].Fd))
			}
		}
	}
}

func (e *epoller) add(id string, cgx interface{}) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	cg, ok := cgx.(cgroups.Cgroup)
	if !ok {
		return fmt.Errorf("expected cgroups.Cgroup, got: %T", cgx)
	}
	fd, err := cg.OOMEventFD()
	if err != nil {
		return err
	}
	e.set[fd] = &item{
		id: id,
		cg: cg,
	}
	event := unix.EpollEvent{
		Fd:     int32(fd),
		Events: unix.EPOLLHUP | unix.EPOLLIN | unix.EPOLLERR,
	}
	return unix.EpollCtl(e.fd, unix.EPOLL_CTL_ADD, int(fd), &event)
}

func (e *epoller) process(ctx context.Context, fd uintptr) {
	flush(fd)
	e.mu.Lock()
	i, ok := e.set[fd]
	if !ok {
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()
	if i.cg.State() == cgroups.Deleted {
		e.mu.Lock()
		delete(e.set, fd)
		e.mu.Unlock()
		unix.Close(int(fd))
		return
	}
	if err := e.publisher.Publish(ctx, runtime.TaskOOMEventTopic, &TaskOOM{
		ContainerID: i.id,
	}); err != nil {
		// Should not happen.
		panic(fmt.Errorf("publish OOM event: %w", err))
	}
}

func flush(fd uintptr) error {
	var buf [8]byte
	_, err := unix.Read(int(fd), buf[:])
	return err
}
