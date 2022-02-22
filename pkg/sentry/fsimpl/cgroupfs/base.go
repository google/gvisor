// Copyright 2021 The gVisor Authors.
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
	"sort"
	"strconv"
	"strings"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

// controllerCommon implements kernel.CgroupController.
//
// Must call init before use.
//
// +stateify savable
type controllerCommon struct {
	ty kernel.CgroupControllerType
	fs *filesystem
}

func (c *controllerCommon) init(ty kernel.CgroupControllerType, fs *filesystem) {
	c.ty = ty
	c.fs = fs
}

func (c *controllerCommon) cloneFrom(other *controllerCommon) {
	c.ty = other.ty
	c.fs = other.fs
}

// Type implements kernel.CgroupController.Type.
func (c *controllerCommon) Type() kernel.CgroupControllerType {
	return kernel.CgroupControllerType(c.ty)
}

// HierarchyID implements kernel.CgroupController.HierarchyID.
func (c *controllerCommon) HierarchyID() uint32 {
	return c.fs.hierarchyID
}

// NumCgroups implements kernel.CgroupController.NumCgroups.
func (c *controllerCommon) NumCgroups() uint64 {
	return atomic.LoadUint64(&c.fs.numCgroups)
}

// Enabled implements kernel.CgroupController.Enabled.
//
// Controllers are currently always enabled.
func (c *controllerCommon) Enabled() bool {
	return true
}

// RootCgroup implements kernel.CgroupController.RootCgroup.
func (c *controllerCommon) RootCgroup() kernel.Cgroup {
	return c.fs.rootCgroup()
}

// controller is an interface for common functionality related to all cgroups.
// It is an extension of the public cgroup interface, containing cgroup
// functionality private to cgroupfs.
type controller interface {
	kernel.CgroupController

	// Clone creates a new controller based on the internal state of the current
	// controller. This is used to initialize a sub-cgroup based on the state of
	// the parent.
	Clone() controller

	// AddControlFiles should extend the contents map with inodes representing
	// control files defined by this controller.
	AddControlFiles(ctx context.Context, creds *auth.Credentials, c *cgroupInode, contents map[string]kernfs.Inode)

	// PrepareMigrate signals the controller that a migration is about to
	// happen. The controller should check for any conditions that would prevent
	// the migration. If PrepareMigrate succeeds, the controller must
	// unconditionally either accept the migration via CommitMigrate, or roll it
	// back via AbortMigrate.
	//
	// Postcondition: If PrepareMigrate returns nil, caller must resolve the
	// migration by calling either CommitMigrate or AbortMigrate.
	PrepareMigrate(t *kernel.Task, src controller) error

	// CommitMigrate completes an in-flight migration.
	//
	// Precondition: Caller must call a corresponding PrepareMigrate.
	CommitMigrate(t *kernel.Task, src controller)

	// AbortMigrate cancels an in-flight migration.
	//
	// Precondition: Caller must call a corresponding PrepareMigrate.
	AbortMigrate(t *kernel.Task, src controller)
}

// cgroupInode implements kernel.CgroupImpl and kernfs.Inode.
//
// +stateify savable
type cgroupInode struct {
	dir

	// controllers is the set of controllers for this cgroup. This is used to
	// store controller-specific state per cgroup. The set of controllers should
	// match the controllers for this hierarchy as tracked by the filesystem
	// object. Immutable.
	controllers map[kernel.CgroupControllerType]controller

	// ts is the list of tasks in this cgroup. The kernel is responsible for
	// removing tasks from this list before they're destroyed, so any tasks on
	// this list are always valid.
	//
	// ts, and cgroup membership in general is protected by fs.tasksMu.
	ts map[*kernel.Task]struct{}
}

var _ kernel.CgroupImpl = (*cgroupInode)(nil)

func (fs *filesystem) newCgroupInode(ctx context.Context, creds *auth.Credentials, parent *cgroupInode) kernfs.Inode {
	c := &cgroupInode{
		dir:         dir{fs: fs},
		ts:          make(map[*kernel.Task]struct{}),
		controllers: make(map[kernel.CgroupControllerType]controller),
	}
	c.dir.cgi = c

	contents := make(map[string]kernfs.Inode)
	contents["cgroup.procs"] = fs.newControllerFile(ctx, creds, &cgroupProcsData{c})
	contents["tasks"] = fs.newControllerFile(ctx, creds, &tasksData{c})

	if parent != nil {
		for ty, ctl := range parent.controllers {
			new := ctl.Clone()
			c.controllers[ty] = new
			new.AddControlFiles(ctx, creds, c, contents)
		}
	} else {
		for _, ctl := range fs.controllers {
			new := ctl.Clone()
			// Uniqueness of controllers enforced by the filesystem on creation.
			c.controllers[ctl.Type()] = new
			new.AddControlFiles(ctx, creds, c, contents)
		}
	}

	c.dir.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|linux.FileMode(0555))
	c.dir.OrderedChildren.Init(kernfs.OrderedChildrenOptions{Writable: true})
	c.dir.IncLinks(c.dir.OrderedChildren.Populate(contents))

	atomic.AddUint64(&fs.numCgroups, 1)

	return c
}

func (c *cgroupInode) HierarchyID() uint32 {
	return c.fs.hierarchyID
}

// Controllers implements kernel.CgroupImpl.Controllers.
func (c *cgroupInode) Controllers() []kernel.CgroupController {
	return c.fs.kcontrollers
}

// tasks returns a snapshot of the tasks inside the cgroup.
func (c *cgroupInode) tasks() []*kernel.Task {
	c.fs.tasksMu.RLock()
	defer c.fs.tasksMu.RUnlock()
	ts := make([]*kernel.Task, 0, len(c.ts))
	for t := range c.ts {
		ts = append(ts, t)
	}
	return ts
}

// Enter implements kernel.CgroupImpl.Enter.
func (c *cgroupInode) Enter(t *kernel.Task) {
	c.fs.tasksMu.Lock()
	c.ts[t] = struct{}{}
	c.fs.tasksMu.Unlock()
}

// Leave implements kernel.CgroupImpl.Leave.
func (c *cgroupInode) Leave(t *kernel.Task) {
	c.fs.tasksMu.Lock()
	delete(c.ts, t)
	c.fs.tasksMu.Unlock()
}

// PrepareMigrate implements kernel.CgroupImpl.PrepareMigrate.
func (c *cgroupInode) PrepareMigrate(t *kernel.Task, src *kernel.Cgroup) error {
	prepared := make([]controller, 0, len(c.controllers))
	rollback := func() {
		for _, p := range prepared {
			c.controllers[p.Type()].AbortMigrate(t, p)
		}
	}

	for srcType, srcCtl := range src.CgroupImpl.(*cgroupInode).controllers {
		ctl := c.controllers[srcType]
		if err := ctl.PrepareMigrate(t, srcCtl); err != nil {
			rollback()
			return err
		}
		prepared = append(prepared, srcCtl)
	}
	return nil
}

// CommitMigrate implements kernel.CgroupImpl.CommitMigrate.
func (c *cgroupInode) CommitMigrate(t *kernel.Task, src *kernel.Cgroup) {
	for srcType, srcCtl := range src.CgroupImpl.(*cgroupInode).controllers {
		c.controllers[srcType].CommitMigrate(t, srcCtl)
	}

	srcI := src.CgroupImpl.(*cgroupInode)
	c.fs.tasksMu.Lock()
	defer c.fs.tasksMu.Unlock()

	delete(srcI.ts, t)
	c.ts[t] = struct{}{}
}

// AbortMigrate implements kernel.CgroupImpl.AbortMigrate.
func (c *cgroupInode) AbortMigrate(t *kernel.Task, src *kernel.Cgroup) {
	for srcType, srcCtl := range src.CgroupImpl.(*cgroupInode).controllers {
		c.controllers[srcType].AbortMigrate(t, srcCtl)
	}
}

func (c *cgroupInode) Cgroup(fd *vfs.FileDescription) kernel.Cgroup {
	return kernel.Cgroup{
		Dentry:     fd.Dentry().Impl().(*kernfs.Dentry),
		CgroupImpl: c,
	}
}

func sortTIDs(tids []kernel.ThreadID) {
	sort.Slice(tids, func(i, j int) bool { return tids[i] < tids[j] })
}

// +stateify savable
type cgroupProcsData struct {
	*cgroupInode
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *cgroupProcsData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	t := kernel.TaskFromContext(ctx)
	currPidns := t.ThreadGroup().PIDNamespace()

	pgids := make(map[kernel.ThreadID]struct{})

	for _, task := range d.tasks() {
		// Map dedups pgid, since iterating over all tasks produces multiple
		// entries for the group leaders.
		if pgid := currPidns.IDOfThreadGroup(task.ThreadGroup()); pgid != 0 {
			pgids[pgid] = struct{}{}
		}
	}

	pgidList := make([]kernel.ThreadID, 0, len(pgids))
	for pgid, _ := range pgids {
		pgidList = append(pgidList, pgid)
	}
	sortTIDs(pgidList)

	for _, pgid := range pgidList {
		fmt.Fprintf(buf, "%d\n", pgid)
	}

	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *cgroupProcsData) Write(ctx context.Context, fd *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	tgid, n, err := parseInt64FromString(ctx, src)
	if err != nil {
		return n, err
	}

	t := kernel.TaskFromContext(ctx)
	currPidns := t.ThreadGroup().PIDNamespace()
	targetTG := currPidns.ThreadGroupWithID(kernel.ThreadID(tgid))
	return n, targetTG.MigrateCgroup(d.Cgroup(fd))
}

// +stateify savable
type tasksData struct {
	*cgroupInode
}

// Generate implements vfs.DynamicBytesSource.Generate.
func (d *tasksData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	t := kernel.TaskFromContext(ctx)
	currPidns := t.ThreadGroup().PIDNamespace()

	var pids []kernel.ThreadID

	for _, task := range d.tasks() {
		if pid := currPidns.IDOfTask(task); pid != 0 {
			pids = append(pids, pid)
		}
	}
	sortTIDs(pids)

	for _, pid := range pids {
		fmt.Fprintf(buf, "%d\n", pid)
	}

	return nil
}

// Write implements vfs.WritableDynamicBytesSource.Write.
func (d *tasksData) Write(ctx context.Context, fd *vfs.FileDescription, src usermem.IOSequence, offset int64) (int64, error) {
	tid, n, err := parseInt64FromString(ctx, src)
	if err != nil {
		return n, err
	}

	t := kernel.TaskFromContext(ctx)
	currPidns := t.ThreadGroup().PIDNamespace()
	targetTask := currPidns.TaskWithID(kernel.ThreadID(tid))
	return n, targetTask.MigrateCgroup(d.Cgroup(fd))
}

// parseInt64FromString interprets src as string encoding a int64 value, and
// returns the parsed value.
func parseInt64FromString(ctx context.Context, src usermem.IOSequence) (val, len int64, err error) {
	const maxInt64StrLen = 20 // i.e. len(fmt.Sprintf("%d", math.MinInt64)) == 20

	t := kernel.TaskFromContext(ctx)

	buf := t.CopyScratchBuffer(maxInt64StrLen)
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, int64(n), err
	}
	str := strings.TrimSpace(string(buf[:n]))

	val, err = strconv.ParseInt(str, 10, 64)
	if err != nil {
		// Note: This also handles zero-len writes if offset is beyond the end
		// of src, or src is empty.
		ctx.Warningf("cgroupfs.parseInt64FromString: failed to parse %q: %v", str, err)
		return 0, int64(n), linuxerr.EINVAL
	}

	return val, int64(n), nil
}

// controllerNoopMigrate partially implements controller. It stubs the migration
// methods with noops for a stateless controller.
type controllerNoopMigrate struct{}

// PrepareMigrate implements controller.PrepareMigrate.
func (*controllerNoopMigrate) PrepareMigrate(t *kernel.Task, src controller) error {
	return nil
}

// CommitMigrate implements controller.CommitMigrate.
func (*controllerNoopMigrate) CommitMigrate(t *kernel.Task, src controller) {}

// AbortMigrate implements controller.AbortMigrate.
func (*controllerNoopMigrate) AbortMigrate(t *kernel.Task, src controller) {}
