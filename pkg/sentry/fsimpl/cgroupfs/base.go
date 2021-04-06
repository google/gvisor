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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
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

// Filesystem implements kernel.CgroupController.Filesystem.
func (c *controllerCommon) Filesystem() *vfs.Filesystem {
	return c.fs.VFSFilesystem()
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

	// AddControlFiles should extend the contents map with inodes representing
	// control files defined by this controller.
	AddControlFiles(ctx context.Context, creds *auth.Credentials, c *cgroupInode, contents map[string]kernfs.Inode)
}

// cgroupInode implements kernel.CgroupImpl and kernfs.Inode.
//
// +stateify savable
type cgroupInode struct {
	dir
	fs *filesystem

	// ts is the list of tasks in this cgroup. The kernel is responsible for
	// removing tasks from this list before they're destroyed, so any tasks on
	// this list are always valid.
	//
	// ts, and cgroup membership in general is protected by fs.tasksMu.
	ts map[*kernel.Task]struct{}
}

var _ kernel.CgroupImpl = (*cgroupInode)(nil)

func (fs *filesystem) newCgroupInode(ctx context.Context, creds *auth.Credentials) kernfs.Inode {
	c := &cgroupInode{
		fs: fs,
		ts: make(map[*kernel.Task]struct{}),
	}

	contents := make(map[string]kernfs.Inode)
	contents["cgroup.procs"] = fs.newControllerFile(ctx, creds, &cgroupProcsData{c})
	contents["tasks"] = fs.newControllerFile(ctx, creds, &tasksData{c})

	for _, ctl := range fs.controllers {
		ctl.AddControlFiles(ctx, creds, c, contents)
	}

	c.dir.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), linux.ModeDirectory|linux.FileMode(0555))
	c.dir.OrderedChildren.Init(kernfs.OrderedChildrenOptions{})
	c.dir.InitRefs()
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

	d.fs.tasksMu.RLock()
	defer d.fs.tasksMu.RUnlock()

	for task := range d.ts {
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
func (d *cgroupProcsData) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	// TODO(b/183137098): Payload is the pid for a process to add to this cgroup.
	return src.NumBytes(), nil
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

	d.fs.tasksMu.RLock()
	defer d.fs.tasksMu.RUnlock()

	for task := range d.ts {
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
func (d *tasksData) Write(ctx context.Context, src usermem.IOSequence, offset int64) (int64, error) {
	// TODO(b/183137098): Payload is the pid for a process to add to this cgroup.
	return src.NumBytes(), nil
}
