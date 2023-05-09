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

package kernel

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
)

// EnterInitialCgroups moves t into an initial set of cgroups.
//
// This is analogous to Linux's kernel/cgroup/cgroup.c:cgroup_css_set_fork().
//
// Precondition: t isn't in any cgroups yet, t.cgroups is empty.
func (t *Task) EnterInitialCgroups(parent *Task) {
	var inherit map[Cgroup]struct{}
	if parent != nil {
		parent.mu.Lock()
		defer parent.mu.Unlock()
		inherit = parent.cgroups
	}
	joinSet := t.k.cgroupRegistry.computeInitialGroups(inherit)

	t.mu.NestedLock(taskLockChild)
	defer t.mu.NestedUnlock(taskLockChild)
	// Transfer ownership of joinSet refs to the task's cgset.
	t.cgroups = joinSet
	for c := range t.cgroups {
		// Since t isn't in any cgroup yet, we can skip the check against
		// existing cgroups.
		c.Enter(t)
	}
}

// EnterCgroup moves t into c.
func (t *Task) EnterCgroup(c Cgroup) error {
	newControllers := make(map[CgroupControllerType]struct{})
	for _, ctl := range c.Controllers() {
		newControllers[ctl.Type()] = struct{}{}
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for oldCG := range t.cgroups {
		if oldCG.HierarchyID() == c.HierarchyID() {
			log.Warningf("Cannot enter new cgroup %v due to conflicting controllers. Try migrate instead?", c)
			return linuxerr.EBUSY
		}
	}

	// No migration required.
	t.enterCgroupLocked(c)

	return nil
}

// +checklocks:t.mu
func (t *Task) enterCgroupLocked(c Cgroup) {
	c.IncRef()
	t.cgroups[c] = struct{}{}
	c.Enter(t)
}

// +checklocks:t.mu
func (t *Task) enterCgroupIfNotYetLocked(c Cgroup) {
	if _, ok := t.cgroups[c]; ok {
		return
	}
	t.enterCgroupLocked(c)
}

// LeaveCgroups removes t out from all its cgroups.
func (t *Task) LeaveCgroups() {
	t.tg.pidns.owner.mu.Lock() // Prevent migration.
	t.mu.Lock()
	cgs := t.cgroups
	t.cgroups = nil
	for c := range cgs {
		c.Leave(t)
	}
	t.mu.Unlock()
	t.tg.pidns.owner.mu.Unlock()

	for c := range cgs {
		c.decRef()
	}
}

// +checklocks:t.mu
func (t *Task) findCgroupWithMatchingHierarchyLocked(other Cgroup) (Cgroup, bool) {
	for c := range t.cgroups {
		if c.HierarchyID() != other.HierarchyID() {
			continue
		}
		return c, true
	}
	return Cgroup{}, false
}

// CgroupPrepareMigrate starts a cgroup migration for this task to dst. The
// migration must be completed through the returned context.
func (t *Task) CgroupPrepareMigrate(dst Cgroup) (*CgroupMigrationContext, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	src, found := t.findCgroupWithMatchingHierarchyLocked(dst)
	if !found {
		log.Warningf("Cannot migrate to cgroup %v since task %v not currently in target hierarchy %v", dst, t, dst.HierarchyID())
		return nil, linuxerr.EINVAL
	}
	if err := dst.PrepareMigrate(t, &src); err != nil {
		return nil, err
	}
	return &CgroupMigrationContext{
		src: src,
		dst: dst,
		t:   t,
	}, nil
}

// MigrateCgroup migrates all tasks in tg to the dst cgroup. Either all tasks
// are migrated, or none are. Atomicity of migrations wrt cgroup membership
// (i.e. a task can't switch cgroups mid-migration due to another migration) is
// guaranteed because migrations are serialized by TaskSet.mu.
func (tg *ThreadGroup) MigrateCgroup(dst Cgroup) error {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()

	var ctxs []*CgroupMigrationContext

	// Prepare migrations. On partial failure, abort.
	for t := tg.tasks.Front(); t != nil; t = t.Next() {
		ctx, err := t.CgroupPrepareMigrate(dst)
		if err != nil {
			// Rollback.
			for _, ctx := range ctxs {
				ctx.Abort()
			}
			return err
		}
		ctxs = append(ctxs, ctx)
	}

	// All migrations are now guaranteed to succeed.

	for _, ctx := range ctxs {
		ctx.Commit()
	}

	return nil
}

// MigrateCgroup migrates this task to the dst cgroup.
func (t *Task) MigrateCgroup(dst Cgroup) error {
	t.tg.pidns.owner.mu.RLock()
	defer t.tg.pidns.owner.mu.RUnlock()

	ctx, err := t.CgroupPrepareMigrate(dst)
	if err != nil {
		return err
	}
	ctx.Commit()
	return nil
}

// TaskCgroupEntry represents a line in /proc/<pid>/cgroup, and is used to
// format a cgroup for display.
type TaskCgroupEntry struct {
	HierarchyID uint32 `json:"hierarchy_id"`
	Controllers string `json:"controllers,omitempty"`
	Path        string `json:"path,omitempty"`
}

// GetCgroupEntries generates the contents of /proc/<pid>/cgroup as
// a TaskCgroupEntry array.
func (t *Task) GetCgroupEntries() []TaskCgroupEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	cgEntries := make([]TaskCgroupEntry, 0, len(t.cgroups))
	for c := range t.cgroups {
		ctls := c.Controllers()
		ctlNames := make([]string, 0, len(ctls))

		// We're guaranteed to have a valid name, a non-empty controller list,
		// or both.

		// Explicit hierachy name, if any.
		if name := c.Name(); name != "" {
			ctlNames = append(ctlNames, fmt.Sprintf("name=%s", name))
		}

		// Controllers attached to this hierarchy, if any.
		for _, ctl := range ctls {
			ctlNames = append(ctlNames, string(ctl.Type()))
		}

		cgEntries = append(cgEntries, TaskCgroupEntry{
			HierarchyID: c.HierarchyID(),
			Controllers: strings.Join(ctlNames, ","),
			Path:        c.Path(),
		})
	}

	sort.Slice(cgEntries, func(i, j int) bool { return cgEntries[i].HierarchyID > cgEntries[j].HierarchyID })
	return cgEntries
}

// GenerateProcTaskCgroup writes the contents of /proc/<pid>/cgroup for t to buf.
func (t *Task) GenerateProcTaskCgroup(buf *bytes.Buffer) {
	cgEntries := t.GetCgroupEntries()
	for _, cgE := range cgEntries {
		fmt.Fprintf(buf, "%d:%s:%s\n", cgE.HierarchyID, cgE.Controllers, cgE.Path)
	}
}

// +checklocks:t.mu
func (t *Task) chargeLocked(target *Task, ctl CgroupControllerType, res CgroupResourceType, value int64) (bool, Cgroup, error) {
	// Due to the uniqueness of controllers on hierarchies, at most one cgroup
	// in t.cgroups will match.
	for c := range t.cgroups {
		err := c.Charge(target, c.Dentry, ctl, res, value)
		if err == nil {
			c.IncRef()
		}
		return err == nil, c, err
	}
	return false, Cgroup{}, nil
}

// ChargeFor charges t's cgroup on behalf of some other task. Returns
// the cgroup that's charged if any. Returned cgroup has an extra ref
// that's transferred to the caller.
func (t *Task) ChargeFor(other *Task, ctl CgroupControllerType, res CgroupResourceType, value int64) (bool, Cgroup, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.chargeLocked(other, ctl, res, value)
}
