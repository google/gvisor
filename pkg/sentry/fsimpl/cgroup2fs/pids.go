// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cgroup2fs

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	pidMaxLimit       = 4 * 1024 * 1024
	pidLimitUnlimited = pidMaxLimit + 1
)

// +stateify savable
type pids struct {
	c      *cgroup
	parent *pids

	detached atomicbitops.Bool

	// mu protects the fields below.
	mu        pidsMutex `state:"nosave"`
	committed int64
	max       int64
	peak      int64

	localMaxHits atomicbitops.Uint64
	hierMaxHits  atomicbitops.Uint64

	eventsFile      *eventFile
	eventsLocalFile *eventFile
}

// canEnter implements controller.canEnter.
func (p *pids) canEnter(ctx context.Context, t *kernel.Task) bool {
	var failedAt *pids
	for curr := p; curr != nil; curr = curr.parent {
		curr.mu.Lock()
		curr.committed++
		if curr.max != pidLimitUnlimited && curr.committed > curr.max {
			failedAt = curr
			curr.mu.Unlock()
			break
		}
		if curr.committed > curr.peak {
			curr.peak = curr.committed
		}
		curr.mu.Unlock()
	}

	if failedAt != nil {
		for q := p; q != failedAt; q = q.parent {
			q.mu.Lock()
			q.committed--
			q.mu.Unlock()
		}
		failedAt.mu.Lock()
		failedAt.committed--
		failedAt.mu.Unlock()

		failedAt.localMaxHits.Add(1)
		if failedAt.eventsLocalFile != nil {
			failedAt.eventsLocalFile.Notify(ctx)
		}
		for curr := failedAt; curr != nil; curr = curr.parent {
			curr.hierMaxHits.Add(1)
			if curr.eventsFile != nil {
				curr.eventsFile.Notify(ctx)
			}
		}
		return false
	}

	return true
}

// cancelEnter implements controller.cancelEnter.
func (p *pids) cancelEnter(ctx context.Context, t *kernel.Task) {
	for curr := p; curr != nil; curr = curr.parent {
		curr.mu.Lock()
		if curr.committed > 0 {
			curr.committed--
		}
		curr.mu.Unlock()
	}
}

// enter implements controller.enter.
func (p *pids) enter(ctx context.Context, t *kernel.Task) {
	// Already eagerly charged inside canEnter
}

// exit implements controller.exit.
func (p *pids) exit(ctx context.Context, t *kernel.Task) {
	for curr := p; curr != nil; curr = curr.parent {
		curr.mu.Lock()
		if curr.committed > 0 {
			curr.committed--
		}
		curr.mu.Unlock()
	}
}

// getPidsCtrl returns the pids controller for a cgroup.
func getPidsCtrl(cg *cgroup) *pids {
	if cg == nil {
		return nil
	}
	if curSet := cg.closestCtrls.Load(); curSet != nil {
		if ctrl, ok := curSet[kernel.Cgroup2PIDs].(*pids); ok {
			return ctrl
		}
	}
	return nil
}

// canAttach implements controller.canAttach.
func (p *pids) canAttach(ctx context.Context, actx *attachCtx) bool {
	return true
}

// cancelAttach implements controller.cancelAttach.
func (p *pids) cancelAttach(ctx context.Context, actx *attachCtx) {
}

// attach implements controller.attach.
func (p *pids) attach(ctx context.Context, actx *attachCtx) {
	netChange := make(map[*pids]int64)

	for t := range actx.tasks {
		oldCg := actx.oldNodes[t]
		oldPidsCtrl := getPidsCtrl(oldCg)

		for curr := p; curr != nil; curr = curr.parent {
			netChange[curr]++
		}
		for curr := oldPidsCtrl; curr != nil; curr = curr.parent {
			netChange[curr]--
		}
	}

	for curr, change := range netChange {
		if change != 0 {
			curr.mu.Lock()
			curr.committed += change
			if curr.committed > curr.peak {
				curr.peak = curr.committed
			}
			curr.mu.Unlock()
		}
	}
}

// interfaceFiles implements controller.interfaceFiles.
func (p *pids) interfaceFiles() []interfaceFile {
	return []interfaceFile{
		{
			name:    "pids.events",
			source:  &pidsEvents{p: p},
			perm:    0444,
			isEvent: true,
			onEventCreated: func(inode *eventFile) {
				p.eventsFile = inode
			},
		},
		{
			name:    "pids.events.local",
			source:  &pidsEventsLocal{p: p},
			perm:    0444,
			isEvent: true,
			onEventCreated: func(inode *eventFile) {
				p.eventsLocalFile = inode
			},
		},
		{name: "pids.current", source: &pidsCurrent{p: p}, perm: 0444},
		{name: "pids.max", source: &pidsMax{p: p}, perm: 0644},
		{name: "pids.peak", source: &pidsPeak{p: p}, perm: 0444},
	}
}

// interfaceFileNames implements controller.interfaceFileNames.
func (p *pids) interfaceFileNames() []string {
	return []string{"pids.events", "pids.events.local", "pids.current", "pids.max", "pids.peak"}
}

// +stateify savable
type pidsEvents struct {
	p *pids
}

func (pe *pidsEvents) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "max %d\n", pe.p.hierMaxHits.Load())
	return nil
}

// +stateify savable
type pidsEventsLocal struct {
	p *pids
}

func (pel *pidsEventsLocal) Generate(ctx context.Context, buf *bytes.Buffer) error {
	fmt.Fprintf(buf, "max %d\n", pel.p.localMaxHits.Load())
	return nil
}

// +stateify savable
type pidsCurrent struct {
	p *pids
}

func (pc *pidsCurrent) Generate(ctx context.Context, buf *bytes.Buffer) error {
	pc.p.mu.Lock()
	defer pc.p.mu.Unlock()
	fmt.Fprintf(buf, "%d\n", pc.p.committed)
	return nil
}

// +stateify savable
type pidsMax struct {
	p *pids
}

func (pm *pidsMax) Generate(ctx context.Context, buf *bytes.Buffer) error {
	pm.p.mu.Lock()
	defer pm.p.mu.Unlock()
	if pm.p.max == pidLimitUnlimited {
		buf.WriteString("max\n")
	} else {
		fmt.Fprintf(buf, "%d\n", pm.p.max)
	}
	return nil
}

func (pm *pidsMax) Write(ctx context.Context, fd *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	data := make([]byte, src.NumBytes())
	if _, err := src.CopyIn(ctx, data); err != nil {
		return 0, err
	}
	str := strings.TrimSpace(string(data))
	if str == "max" {
		pm.p.mu.Lock()
		pm.p.max = pidLimitUnlimited
		pm.p.mu.Unlock()
		return int64(len(data)), nil
	}

	val, err := strconv.ParseInt(str, 10, 64)
	if err != nil || val < 0 {
		return 0, linuxerr.EINVAL
	}

	pm.p.mu.Lock()
	pm.p.max = val
	pm.p.mu.Unlock()
	return int64(len(data)), nil
}

// +stateify savable
type pidsPeak struct {
	p *pids
}

func (pp *pidsPeak) Generate(ctx context.Context, buf *bytes.Buffer) error {
	pp.p.mu.Lock()
	defer pp.p.mu.Unlock()
	fmt.Fprintf(buf, "%d\n", pp.p.peak)
	return nil
}

// detach implements controller.detach.
func (p *pids) detach() {
	p.detached.Store(true)
}

// isActive implements controller.isActive.
func (p *pids) isActive() bool {
	return !p.detached.Load()
}
