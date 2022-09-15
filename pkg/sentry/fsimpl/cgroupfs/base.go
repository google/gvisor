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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
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
	// parent is the parent controller if any. Immutable.
	//
	// Note that we don't have to update this on renames, since cgroup
	// directories can't be moved to a different parent directory.
	parent controller
}

func (c *controllerCommon) init(ty kernel.CgroupControllerType, fs *filesystem) {
	c.ty = ty
	c.fs = fs
}

func (c *controllerCommon) cloneFromParent(parent controller) {
	c.ty = parent.Type()
	c.fs = parent.Filesystem()
	c.parent = parent
}

// Filesystem implements controller.Filesystem.
func (c *controllerCommon) Filesystem() *filesystem {
	return c.fs
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
	return c.fs.numCgroups.Load()
}

// Enabled implements kernel.CgroupController.Enabled.
//
// Controllers are currently always enabled.
func (c *controllerCommon) Enabled() bool {
	return true
}

// EffectiveRootCgroup implements kernel.CgroupController.EffectiveRootCgroup.
func (c *controllerCommon) EffectiveRootCgroup() kernel.Cgroup {
	return c.fs.effectiveRootCgroup()
}

// controller is an interface for common functionality related to all cgroups.
// It is an extension of the public cgroup interface, containing cgroup
// functionality private to cgroupfs.
type controller interface {
	kernel.CgroupController

	// Filesystem returns the cgroupfs filesystem backing this controller.
	Filesystem() *filesystem

	// Clone creates a new controller based on the internal state of this
	// controller. This is used to initialize a sub-cgroup based on the state of
	// the parent.
	Clone() controller

	// AddControlFiles should extend the contents map with inodes representing
	// control files defined by this controller.
	AddControlFiles(ctx context.Context, creds *auth.Credentials, c *cgroupInode, contents map[string]kernfs.Inode)

	// Enter is called when a task initially moves into a cgroup. This is
	// distinct from migration because the task isn't migrating away from a
	// cgroup. Enter is called when a task is created and joins its initial
	// cgroup, or when cgroupfs is mounted and existing tasks are moved into
	// cgroups.
	Enter(t *kernel.Task)

	// Leave is called when a task leaves a cgroup. This is distinct from
	// migration because the task isn't migrating to another cgroup. Leave is
	// called when a task exits.
	Leave(t *kernel.Task)

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

	// Charge charges a controller for a particular resource. The implementation
	// should panic if passed a resource type they do not control.
	Charge(t *kernel.Task, d *kernfs.Dentry, res kernel.CgroupResourceType, value int64) error
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

func (fs *filesystem) newCgroupInode(ctx context.Context, creds *auth.Credentials, parent *cgroupInode, mode linux.FileMode) kernfs.Inode {
	c := &cgroupInode{
		dir:         dir{fs: fs},
		ts:          make(map[*kernel.Task]struct{}),
		controllers: make(map[kernel.CgroupControllerType]controller),
	}
	c.dir.cgi = c

	contents := make(map[string]kernfs.Inode)
	contents["cgroup.procs"] = fs.newControllerWritableFile(ctx, creds, &cgroupProcsData{c}, false)
	contents["tasks"] = fs.newControllerWritableFile(ctx, creds, &tasksData{c}, false)

	if parent != nil {
		for ty, ctl := range parent.controllers {
			new := ctl.Clone()
			c.controllers[ty] = new
			new.AddControlFiles(ctx, creds, c, contents)
		}
	} else {
		for _, ctl := range fs.controllers {
			// Uniqueness of controllers enforced by the filesystem on
			// creation. The root cgroup uses the controllers directly from the
			// filesystem.
			c.controllers[ctl.Type()] = ctl
			ctl.AddControlFiles(ctx, creds, c, contents)
		}
	}

	c.dir.InodeAttrs.Init(ctx, creds, linux.UNNAMED_MAJOR, fs.devMinor, fs.NextIno(), mode)
	c.dir.OrderedChildren.Init(kernfs.OrderedChildrenOptions{Writable: true})
	c.dir.IncLinks(c.dir.OrderedChildren.Populate(contents))

	fs.numCgroups.Add(1)

	return c
}

// HierarchyID implements kernel.CgroupImpl.HierarchyID.
func (c *cgroupInode) HierarchyID() uint32 {
	return c.fs.hierarchyID
}

// Name implements kernel.CgroupImpl.Name.
func (c *cgroupInode) Name() string {
	return c.fs.hierarchyName
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
	defer c.fs.tasksMu.Unlock()

	c.ts[t] = struct{}{}
	for _, ctl := range c.controllers {
		ctl.Enter(t)
	}
}

// Leave implements kernel.CgroupImpl.Leave.
func (c *cgroupInode) Leave(t *kernel.Task) {
	c.fs.tasksMu.Lock()
	defer c.fs.tasksMu.Unlock()

	for _, ctl := range c.controllers {
		ctl.Leave(t)
	}
	delete(c.ts, t)
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
	c.fs.tasksMu.Lock()
	defer c.fs.tasksMu.Unlock()

	for srcType, srcCtl := range src.CgroupImpl.(*cgroupInode).controllers {
		c.controllers[srcType].CommitMigrate(t, srcCtl)
	}

	srcI := src.CgroupImpl.(*cgroupInode)
	delete(srcI.ts, t)
	c.ts[t] = struct{}{}
}

// AbortMigrate implements kernel.CgroupImpl.AbortMigrate.
func (c *cgroupInode) AbortMigrate(t *kernel.Task, src *kernel.Cgroup) {
	for srcType, srcCtl := range src.CgroupImpl.(*cgroupInode).controllers {
		c.controllers[srcType].AbortMigrate(t, srcCtl)
	}
}

// CgroupFromControlFileFD returns a cgroup object given a control file FD for the cgroup.
func (c *cgroupInode) CgroupFromControlFileFD(fd *vfs.FileDescription) kernel.Cgroup {
	controlFileDentry := fd.Dentry().Impl().(*kernfs.Dentry)
	// The returned parent dentry remains valid without holding locks because in
	// cgroupfs, the parent directory relationship of a control file is
	// effectively immutable. Control files cannot be unlinked, renamed or
	// destroyed independently from their parent directory.
	parentD := controlFileDentry.Parent()
	return kernel.Cgroup{
		Dentry:     parentD,
		CgroupImpl: c,
	}
}

// Charge implements kernel.CgroupImpl.Charge.
//
// Charge notifies a matching controller of a change in resource usage. Due to
// the uniqueness of controllers, at most one controller will match. If no
// matching controller is present in this directory, the call silently
// succeeds. The caller should call Charge on all hierarchies to ensure any
// matching controller across the entire system is charged.
func (c *cgroupInode) Charge(t *kernel.Task, d *kernfs.Dentry, ctlType kernel.CgroupControllerType, res kernel.CgroupResourceType, value int64) error {
	c.fs.tasksMu.RLock()
	defer c.fs.tasksMu.RUnlock()
	if ctl, ok := c.controllers[ctlType]; ok {
		return ctl.Charge(t, d, res, value)
	}
	return nil
}

// ReadControl implements kernel.CgroupImpl.ReadControl.
func (c *cgroupInode) ReadControl(ctx context.Context, name string) (string, error) {
	c.fs.tasksMu.RLock()
	defer c.fs.tasksMu.RUnlock()

	cfi, err := c.Lookup(ctx, name)
	if err != nil {
		return "", fmt.Errorf("no such control file")
	}
	cbf, ok := cfi.(controllerFileImpl)
	if !ok {
		return "", fmt.Errorf("no such control file")
	}
	if !cbf.AllowBackgroundAccess() {
		return "", fmt.Errorf("this control may not be accessed from a background context")
	}

	var buf bytes.Buffer
	err = cbf.Source().Data().Generate(ctx, &buf)
	return buf.String(), err
}

// WriteControl implements kernel.CgroupImpl.WriteControl.
func (c *cgroupInode) WriteControl(ctx context.Context, name string, value string) error {
	c.fs.tasksMu.RLock()
	defer c.fs.tasksMu.RUnlock()

	cfi, err := c.Lookup(ctx, name)
	if err != nil {
		return fmt.Errorf("no such control file")
	}
	// Do the more general cast first so we can give a meaningful error message when
	// the control file exists, but isn't accessible (either due to being
	// unwritable, or not being available from a background context).
	cbf, ok := cfi.(controllerFileImpl)
	if !ok {
		return fmt.Errorf("no such control file")
	}
	if !cbf.AllowBackgroundAccess() {
		return fmt.Errorf("this control may not be accessed from a background context")
	}
	wcbf, ok := cfi.(writableControllerFileImpl)
	if !ok {
		return fmt.Errorf("control file not writable")
	}

	ioSeq := usermem.BytesIOSequence([]byte(value))
	n, err := wcbf.WriteBackground(ctx, ioSeq)
	if err != nil {
		return err
	}
	if n != int64(len(value)) {
		return fmt.Errorf("short write")
	}

	return nil
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
	for pgid := range pgids {
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
	var targetTG *kernel.ThreadGroup
	if tgid != 0 {
		targetTG = currPidns.ThreadGroupWithID(kernel.ThreadID(tgid))
	} else {
		targetTG = t.ThreadGroup()
	}

	if targetTG == nil {
		return 0, linuxerr.EINVAL
	}
	return n, targetTG.MigrateCgroup(d.CgroupFromControlFileFD(fd))
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
	var targetTask *kernel.Task
	if tid != 0 {
		targetTask = currPidns.TaskWithID(kernel.ThreadID(tid))
	} else {
		targetTask = t
	}
	if targetTask == nil {
		return 0, linuxerr.EINVAL
	}
	return n, targetTask.MigrateCgroup(d.CgroupFromControlFileFD(fd))
}

// parseInt64FromString interprets src as string encoding a int64 value, and
// returns the parsed value.
func parseInt64FromString(ctx context.Context, src usermem.IOSequence) (val, len int64, err error) {
	const maxInt64StrLen = 20 // i.e. len(fmt.Sprintf("%d", math.MinInt64)) == 20

	buf := copyScratchBufferFromContext(ctx, maxInt64StrLen)
	n, err := src.CopyIn(ctx, buf)
	if err != nil {
		return 0, int64(n), err
	}
	str := strings.TrimSpace(string(buf[:n]))

	val, err = strconv.ParseInt(str, 10, 64)
	if err != nil {
		// Note: This also handles zero-len writes if offset is beyond the end
		// of src, or src is empty.
		ctx.Debugf("cgroupfs.parseInt64FromString: failed to parse %q: %v", str, err)
		return 0, int64(n), linuxerr.EINVAL
	}

	return val, int64(n), nil
}

// copyScratchBufferFromContext returns a scratch buffer of the given size. It
// tries to use the task's copy scratch buffer if we're on a task context,
// otherwise it allocates a new buffer.
func copyScratchBufferFromContext(ctx context.Context, size int) []byte {
	t := kernel.TaskFromContext(ctx)
	if t != nil {
		return t.CopyScratchBuffer(hostarch.PageSize)
	}
	// Not on task context.
	return make([]byte, hostarch.PageSize)
}

// controllerStateless partially implements controller. It stubs the migration
// methods with noops for a stateless controller.
type controllerStateless struct{}

// Enter implements controller.Enter.
func (*controllerStateless) Enter(t *kernel.Task) {}

// Leave implements controller.Leave.
func (*controllerStateless) Leave(t *kernel.Task) {}

// PrepareMigrate implements controller.PrepareMigrate.
func (*controllerStateless) PrepareMigrate(t *kernel.Task, src controller) error {
	return nil
}

// CommitMigrate implements controller.CommitMigrate.
func (*controllerStateless) CommitMigrate(t *kernel.Task, src controller) {}

// AbortMigrate implements controller.AbortMigrate.
func (*controllerStateless) AbortMigrate(t *kernel.Task, src controller) {}

// controllerNoResource partially implements controller. It stubs out the Charge
// method for controllers that don't track resource usage through the charge
// mechanism.
type controllerNoResource struct{}

// Charge implements controller.Charge.
func (*controllerNoResource) Charge(t *kernel.Task, d *kernfs.Dentry, res kernel.CgroupResourceType, value int64) error {
	panic(fmt.Sprintf("cgroupfs: Attempted to charge a controller with unknown resource %v for value %v", res, value))
}
