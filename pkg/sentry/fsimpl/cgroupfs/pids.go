// Copyright 2022 The gVisor Authors.
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

package cgroupfs

import (
	"bytes"
	"fmt"
	"strings"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// pidMaxLimit is the maximum number of pids allowed on a 64-bit system. The
// practical limit is much lower. See Linux, include/linux/threads.h.
const pidMaxLimit = 4 * 1024 * 1024
const pidLimitUnlimited = pidMaxLimit + 1

// pidsController tracks how many pids are used by tasks in a cgroup. This is
// used to limit the number of tasks per cgroup. The limit is enforced only when
// new tasks are created via Fork/Clone. Task migrations and limit changes can
// cause the current number of pids to exceed the limit.
//
// A task can charge a PIDs cgroup in two ways:
//
//  1. A task created prior to the PIDs controller being enabled, or created
//     through kernel.CreateProcess (i.e. not from userspace) directly add
//     committed charges via the Enter method.
//
//  2. A task created through Task.Clone (i.e. userspace fork/clone) first add a
//     pending charge through the Charge method. This is a temporary reservation
//     which ensures the cgroup has enough space to allow the task to start. Once
//     the task startup succeeds, it calls Enter and consumes the reservation.
//
// +stateify savable
type pidsController struct {
	controllerCommon

	// isRoot indiciates if this is the root cgroup in its hierarchy. Immutable
	// since cgroupfs doesn't allow cross directory renames.
	isRoot bool

	// mu protects the fields below.
	mu pidsControllerMutex `state:"nosave"`

	// pendingTotal and pendingPool tracks the charge for processes starting
	// up. During startup, we check if PIDs are available by charging the
	// cgroup. However, the process actually joins the cgroup as a later point
	// via Enter. We keep a count of the charges we allocated via Charge, and
	// use this pool to account for already accounted charges from Enter.
	//
	// We also track which task owns the pending charge so we can cancel the
	// charge if a task creation fails after the Charge call.
	//
	// pendingTotal and pendingPool are both protected by mu.
	pendingTotal int64
	pendingPool  map[*kernel.Task]int64

	// committed represent charges for tasks that have already started and
	// called Enter. Protected by mu.
	committed int64

	// max is the PID limit for this cgroup. Protected by mu.
	max int64
}

var _ controller = (*pidsController)(nil)

// newRootPIDsController creates the root node for a PIDs cgroup. Child
// directories should be created through Clone.
func newRootPIDsController(fs *filesystem) *pidsController {
	c := &pidsController{
		isRoot:      true,
		max:         pidLimitUnlimited,
		pendingPool: make(map[*kernel.Task]int64),
	}
	c.controllerCommon.init(kernel.CgroupControllerPIDs, fs)
	return c
}

// Clone implements controller.Clone.
func (c *pidsController) Clone() controller {
	c.mu.Lock()
	defer c.mu.Unlock()
	new := &pidsController{
		isRoot:      false,
		max:         pidLimitUnlimited,
		pendingPool: make(map[*kernel.Task]int64),
	}
	new.controllerCommon.cloneFromParent(c)
	return new
}

// AddControlFiles implements controller.AddControlFiles.
func (c *pidsController) AddControlFiles(ctx context.Context, creds *auth.Credentials, _ *cgroupInode, contents map[string]kernfs.Inode) {
	contents["pids.current"] = c.fs.newControllerFile(ctx, creds, &pidsCurrentData{c: c}, true)
	if !c.isRoot {
		// "This is not available in the root cgroup for obvious reasons" --
		// Linux, Documentation/cgroup-v1/pids.txt.
		contents["pids.max"] = c.fs.newControllerWritableFile(ctx, creds, &pidsMaxData{c: c}, true)
	}
}

// Enter implements controller.Enter.
//
// Enter attempts to commit a charge from the pending pool. If at least one
// charge is pending for t, one pending charge is converted to a commited
// charge, and the net change in total charges is zero. If no charge is pending,
// a new charge is added directly to the committed pool.
func (c *pidsController) Enter(t *kernel.Task) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if pending, ok := c.pendingPool[t]; ok {
		if pending == 1 {
			delete(c.pendingPool, t)
		} else {
			c.pendingPool[t] = pending - 1
		}
		c.pendingTotal--
		if c.pendingTotal < 0 {
			panic(fmt.Sprintf("cgroupfs: pids controller has negative pending charge: %v\n", c.committed))
		}
	}

	// Either we're converting a pending charge from above, or generating a new
	// committed charge directly here. Either way, we don't enforce the limit on
	// Enter.
	c.committed++
}

// Leave implements controller.Leave.
func (c *pidsController) Leave(t *kernel.Task) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.committed <= 0 {
		panic(fmt.Sprintf("cgroupfs: pids controller committed charge underflow on Leave for task %+v", t))
	}
	c.committed--
}

// PrepareMigrate implements controller.PrepareMigrate.
func (c *pidsController) PrepareMigrate(t *kernel.Task, src controller) error {
	srcC := src.(*pidsController)
	srcC.mu.Lock()
	defer srcC.mu.Unlock()

	if _, ok := srcC.pendingPool[t]; ok {
		// Migrating task isn't fully initialized, return transient failure.
		return linuxerr.EAGAIN
	}

	return nil
}

// CommitMigrate implements controller.CommitMigrate.
//
// Migrations can cause a cgroup to exceed its limit. CommitMigrate can only be
// called for tasks with committed charges, PrepareMigrate will deny migrations
// prior to Enter.
func (c *pidsController) CommitMigrate(t *kernel.Task, src controller) {
	// Note: The charge is allowed to exceed max on migration. The charge may
	// not exceed max when incurred due to a fork/clone, which will call
	// pidsController.Charge().
	c.mu.Lock()
	c.committed++
	c.mu.Unlock()

	srcC := src.(*pidsController)
	srcC.mu.Lock()
	if srcC.committed <= 0 {
		panic(fmt.Sprintf("cgroupfs: pids controller committed charge underflow on CommitMigrate for task %+v on the source cgroup", t))
	}
	srcC.committed--
	srcC.mu.Unlock()
}

// AbortMigrate implements controller.AbortMigrate.
func (c *pidsController) AbortMigrate(t *kernel.Task, src controller) {}

// Charge implements controller.Charge. This manipulates the pending
// pool. Charge are committed from the pending pool by Enter. The caller is
// responsible for ensuring negative charges correspond to previous positive
// charges. Negative charges that cause an underflow result in a panic.
func (c *pidsController) Charge(t *kernel.Task, d *kernfs.Dentry, res kernel.CgroupResourceType, value int64) error {
	if res != kernel.CgroupResourcePID {
		panic(fmt.Sprintf("cgroupfs: pids controller invalid resource type %v", res))
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Negative charge.
	if value < 0 {
		if c.pendingTotal+value < 0 {
			panic(fmt.Sprintf("cgroupfs: pids controller pending pool would be negative if charge was allowed: current pool: %d, proposed charge: %d, path: %q, task: %p", c.pendingTotal, value, d.FSLocalPath(), t))
		}

		pending, ok := c.pendingPool[t]
		if !ok {
			panic(fmt.Sprintf("cgroupfs: pids controller attempted to remove pending charge for Task %p, but task didn't have pending charges, path: %q", t, d.FSLocalPath()))
		}
		if pending+value < 0 {
			panic(fmt.Sprintf("cgroupfs: pids controller attempted to remove pending charge for Task %p, but task didn't have enough pending charges; current charges: %d, proposed charge: %d, path: %q", t, pending, value, d.FSLocalPath()))

		}

		c.pendingPool[t] += value
		c.pendingTotal += value
		return nil
	}

	// Positive charge.
	new := c.committed + c.pendingTotal + value
	if new > c.max {
		log.Debugf("cgroupfs: pids controller charge denied due to limit: path: %q, requested: %d, current: %d (pending: %v, committed: %v), max: %v",
			d.FSLocalPath(), value, c.committed+c.pendingTotal, c.pendingTotal, c.committed, c.max)
		return linuxerr.EAGAIN
	}

	c.pendingPool[t] += value
	c.pendingTotal += value
	return nil
}

// +stateify savable
type pidsCurrentData struct {
	c *pidsController
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *pidsCurrentData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	d.c.mu.Lock()
	defer d.c.mu.Unlock()
	fmt.Fprintf(buf, "%d\n", d.c.committed+d.c.pendingTotal)
	return nil
}

// +stateify savable
type pidsMaxData struct {
	c *pidsController
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *pidsMaxData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	d.c.mu.Lock()
	defer d.c.mu.Unlock()

	if d.c.max > pidMaxLimit {
		fmt.Fprintf(buf, "max\n")
	} else {
		fmt.Fprintf(buf, "%d\n", d.c.max)
	}

	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *pidsMaxData) Write(ctx context.Context, _ *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	return d.WriteBackground(ctx, src)
}

// WriteBackground implements writableControllerFileImpl.WriteBackground.
func (d *pidsMaxData) WriteBackground(ctx context.Context, src usermem.IOSequence) (int64, error) {
	buf := copyScratchBufferFromContext(ctx, hostarch.PageSize)
	ncpy, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, err
	}
	if strings.TrimSpace(string(buf)) == "max" {
		d.c.mu.Lock()
		defer d.c.mu.Unlock()
		d.c.max = pidLimitUnlimited
		return int64(ncpy), nil
	}

	val, n, err := parseInt64FromString(ctx, src)
	if err != nil {
		return 0, linuxerr.EINVAL
	}
	if val < 0 || val > pidMaxLimit {
		return 0, linuxerr.EINVAL
	}

	d.c.mu.Lock()
	defer d.c.mu.Unlock()
	d.c.max = val
	return int64(n), nil
}
