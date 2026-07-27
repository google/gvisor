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
	"math"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"

	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// Aliased for brevity.
const (
	firstController = kernel.Cgroup2Ctrl(0)
	numControllers  = kernel.Cgroup2NumControllers
)

var ctrlNames = map[string]kernel.Cgroup2Ctrl{
	"cpu":    kernel.Cgroup2CPU,
	"memory": kernel.Cgroup2Memory,
	"pids":   kernel.Cgroup2PIDs,
	"cpuset": kernel.Cgroup2CPUSet,
}

var ctrlTypeStr = map[kernel.Cgroup2Ctrl]string{
	kernel.Cgroup2CPU:    "cpu",
	kernel.Cgroup2Memory: "memory",
	kernel.Cgroup2PIDs:   "pids",
	kernel.Cgroup2CPUSet: "cpuset",
}

// ctrlSet is an array mapping ctrlTypes to their matching active controller instances.
type ctrlSet [kernel.Cgroup2NumControllers]controller

func (cs *ctrlSet) fork() *ctrlSet {
	clone := *cs
	return &clone
}

// interfaceFile defines a cgroup interface file to be instantiated.
type interfaceFile struct {
	name           string
	source         vfs.DynamicBytesSource
	perm           linux.FileMode
	isEvent        bool
	onEventCreated func(inode *eventFile)
	showAtRoot     bool
	ctrl           controller
}

type attachCtx struct {
	tasks    map[*kernel.Task]struct{}
	oldNodes map[*kernel.Task]*cgroup
}

// controller is an interface for a cgroup subsystem controller.
type controller interface {
	// Task lifecycle operations.
	// Invoked during CreateProcess, clone(), exit() etc.
	canEnter(ctx context.Context, t *kernel.Task) bool
	cancelEnter(ctx context.Context, t *kernel.Task)
	enter(ctx context.Context, t *kernel.Task)
	exit(ctx context.Context, t *kernel.Task)

	// Task migration operations.
	// Invoked by cgroup v2 admin operations.
	canAttach(ctx context.Context, actx *attachCtx) bool
	cancelAttach(ctx context.Context, actx *attachCtx)
	attach(ctx context.Context, actx *attachCtx)

	// interfaceFiles returns definitions for tailored interface files specific to this controller.
	interfaceFiles() []interfaceFile

	// interfaceFileNames returns the names of the interface files tied to this controller.
	interfaceFileNames() []string

	// detach marks this controller instance as detached/disabled.
	detach()

	// isActive returns true if the hosting cgroup hasn't detached this controller yet.
	isActive() bool
}

// newController instantiates a new controller of the given type for the specified cgroup.
// +checklocksread:c.fs.treeMu
func (c *cgroup) newController(cType kernel.Cgroup2Ctrl) controller {
	var parent controller
	if c.parent != nil {
		parent = c.parent.ctrls[cType] // +checklocksforce: c.fs.treeMu is locked
		if parent == nil {
			panic("unified cgroups inconsistency: parent controller is nil")
		}
	}

	switch cType {
	case kernel.Cgroup2CPU:
		var cpuParent *cpu
		if parent != nil {
			cpuParent = parent.(*cpu)
		}
		cc := &cpu{
			c:               c,
			parent:          cpuParent,
			baselineCharges: make(map[*kernel.Task]usage.CPUStats),
		}
		cc.weight.Store(100)
		cc.maxUSec.Store(math.MaxInt64)
		cc.periodUSec.Store(100000)
		return cc
	case kernel.Cgroup2Memory:
		var memParent *memory
		if parent != nil {
			memParent = parent.(*memory)
		}
		memCtrl := &memory{c: c, parent: memParent, id: c.fs.nextMemoryID()}
		memCtrl.maxBytes.Store(math.MaxInt64)
		memCtrl.highBytes.Store(math.MaxInt64)
		return memCtrl
	case kernel.Cgroup2PIDs:
		var pidsParent *pids
		if parent != nil {
			pidsParent = parent.(*pids)
		}
		return &pids{
			c:      c,
			parent: pidsParent,
			max:    pidLimitUnlimited,
		}
	case kernel.Cgroup2CPUSet:
		var cpusetParent *cpuset
		if parent != nil {
			cpusetParent = parent.(*cpuset)
		}
		return &cpuset{c: c, parent: cpusetParent}
	default:
		return nil
	}
}
