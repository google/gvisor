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

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
)

// EnterInitialV1Cgroups moves t into an initial set of cgroups.
// If initCgroups is not nil, the new task will be placed in the specified cgroups.
// Otherwise, if parent is not nil, the new task will be placed in the parent's cgroups.
// If neither is specified, the new task will be in the root cgroups.
//
// This is analogous to Linux's kernel/cgroup/cgroup.c:cgroup_css_set_fork().
//
// Precondition: t isn't in any cgroups yet, t.cgroups is empty.
func (t *Task) EnterInitialV1Cgroups(parent *Task, initCgroups map[Cgroup]struct{}) {
	var inherit map[Cgroup]struct{}
	if initCgroups != nil {
		inherit = initCgroups
	} else if parent != nil {
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
		t.SetMemCgIDFromCgroup(c)
	}
}

// FreezeCreditDelta indicates how SetCgroupFrozen(Locked) changed a task's
// outstanding freeze credit, so the caller (which owns cgroup2fs's
// pending-freeze counter) can adjust it -- kernel can't touch cgroup2fs
// directly, hence the explicit return value.
type FreezeCreditDelta int

const (
	// FreezeCreditNone: no change (state didn't change, or t was already
	// parked, so its credit was already resolved).
	FreezeCreditNone FreezeCreditDelta = iota
	// FreezeCreditIssue: caller must record one new outstanding credit,
	// charged to the cgroup whose state was just relayed.
	FreezeCreditIssue
	// FreezeCreditRetract: caller must retract one outstanding credit --
	// resolved either by t actually parking, or by t being thawed,
	// exited, or migrated before it could.
	FreezeCreditRetract
)

// SetCgroupFrozenLocked is SetCgroupFrozen's fs.tasksMu-precondition
// counterpart: for callers (freeze(), attach()) that already hold
// cgroup2fs's pending-freeze counter lock and apply the returned delta
// themselves within the same critical section.
//
// cg is the relaying cgroup (recorded as the credit's owner if one is
// issued). The returned Cgroup2 for a retract is whichever cgroup actually
// issued the credit -- never assume it's cg, t may have migrated since.
//
// Lock ordering: callers hold fs.tasksMu; this takes signalHandlers.mu
// (fs.tasksMu -> signalHandlers.mu, matching kill() -> SendSignal).
func (t *Task) SetCgroupFrozenLocked(cg Cgroup2, frozen bool) (FreezeCreditDelta, Cgroup2) {
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	return t.setCgroupFrozenLocked(cg, frozen)
}

// SetCgroupFrozen relays the effective cgroup v2 freeze state into the task
// and reconciles its stop state, mirroring groupStop: on freeze it
// interrupts the task so it parks itself in frozenStop (a task can only
// stop its own goroutine); on thaw it authoritatively ends the stop, since
// a parked task can't wake itself.
//
// For callers without the pending-freeze-counter lock held (namely
// task_start.go's fork-into-frozen-subtree path). Relays through
// Cgroup2.SetTaskFrozen, which takes fs.tasksMu, calls back into
// SetCgroupFrozenLocked, and adjusts the counter itself -- preserving the
// same fs.tasksMu -> signalHandlers.mu order as the direct callers.
func (t *Task) SetCgroupFrozen(ctx context.Context, frozen bool) {
	if cg := t.Cgroup2(); cg != nil {
		cg.SetTaskFrozen(ctx, t, frozen)
	}
}

// Preconditions: signalHandlers.mu is locked.
func (t *Task) setCgroupFrozenLocked(cg Cgroup2, frozen bool) (FreezeCreditDelta, Cgroup2) {
	was := t.frozen
	t.frozen = frozen
	delta := FreezeCreditNone
	var creditCg Cgroup2
	if frozen {
		if !was {
			t.pendingFreezeCredit = true
			t.pendingFreezeCgroup = cg
			delta = FreezeCreditIssue
			creditCg = cg
		}
		// Self-service enter: t parks itself via runInterrupt. Called
		// even if already frozen -- interrupt() is deduplicated, and a
		// group-stop ending relies on this to re-check frozenStop.
		t.interrupt()
	} else if was {
		if _, ok := t.stop.(*frozenStop); ok {
			// Authoritative end (mirrors endGroupStopLocked on SIGCONT):
			// a parked task can't leave its own stop; its credit, if
			// any, was already retracted at park time.
			t.endInternalStopLocked()
		} else if t.pendingFreezeCredit {
			// Thawed before parking: runInterrupt will never resolve
			// this now, so retract here -- from whichever cgroup
			// actually issued it, not cg (t may have migrated since).
			creditCg = t.pendingFreezeCgroup
			t.pendingFreezeCredit = false
			t.pendingFreezeCgroup = nil
			delta = FreezeCreditRetract
		}
	}
	return delta, creditCg
}

// SetCgroupFrozenLockedForMigration is attach()'s counterpart to
// SetCgroupFrozenLocked for the one case a single (delta, Cgroup2) pair
// can't express: a task with an outstanding, unparked credit that migrates
// to newCg while staying frozen. t.frozen doesn't change, so the normal
// issue/retract branches never fire, silently stranding the old cgroup's
// counter. This detects that case and moves the credit instead, leaving
// t.frozen/t.pendingFreezeCredit otherwise untouched.
//
// Must be one atomic operation: reading and acting in two separate
// signalHandlers.mu acquisitions would race runInterrupt actually parking
// (and resolving the credit) in between, double-resolving it.
//
// The second (delta, Cgroup2) pair is (FreezeCreditNone, nil) except in the
// migration case above; apply both, in either order.
//
// Lock ordering: callers hold fs.tasksMu; this then takes
// signalHandlers.mu.
func (t *Task) SetCgroupFrozenLockedForMigration(newCg Cgroup2, newEff bool) (FreezeCreditDelta, Cgroup2, FreezeCreditDelta, Cgroup2) {
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()

	was := t.frozen
	oldOwner := t.pendingFreezeCgroup
	// Read before setCgroupFrozenLocked's call below, which never touches
	// this field in the was && frozen branch, so the value is unaffected.
	stillOwed := was && newEff && t.pendingFreezeCredit && oldOwner != newCg

	delta1, cg1 := t.setCgroupFrozenLocked(newCg, newEff)

	if stillOwed && delta1 == FreezeCreditNone {
		t.pendingFreezeCgroup = newCg
		t.interrupt()
		return FreezeCreditRetract, oldOwner, FreezeCreditIssue, newCg
	}
	return delta1, cg1, FreezeCreditNone, nil
}

// resolveFreezeCreditLocked clears and returns t's outstanding freeze
// credit, called by runInterrupt once t has parked in frozenStop: parking
// is what pays off the credit. Unlike setCgroupFrozenLocked, this never
// touches t.frozen or t.stop.
//
// Preconditions: signalHandlers.mu is locked.
func (t *Task) resolveFreezeCreditLocked() (FreezeCreditDelta, Cgroup2) {
	if !t.pendingFreezeCredit {
		return FreezeCreditNone, nil
	}
	cg := t.pendingFreezeCgroup
	t.pendingFreezeCredit = false
	t.pendingFreezeCgroup = nil
	return FreezeCreditRetract, cg
}

// ResolveFreezeCreditLocked is resolveFreezeCreditLocked's
// fs.tasksMu-precondition counterpart, for cgroup2fs's Exit() (holds
// fs.tasksMu, not signalHandlers.mu, on task death). Without this, a task
// that dies before parking (e.g. SIGKILLed while frozen but unparked) would
// leak its credit forever.
//
// Unlike runInterrupt's park path, which must defer applying the delta to
// avoid inverting lock order, Exit() already holds fs.tasksMu, so apply the
// result inline, in the same critical section.
//
// Lock ordering: callers hold fs.tasksMu; this then takes
// signalHandlers.mu.
func (t *Task) ResolveFreezeCreditLocked() (FreezeCreditDelta, Cgroup2) {
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()
	return t.resolveFreezeCreditLocked()
}

// SetMemCgID sets the given memory cgroup id to the task.
func (t *Task) SetMemCgID(memCgID uint32) {
	t.memCgID.Store(memCgID)
}

// SetMemCgIDFromCgroup sets the id of the given memory cgroup to the task.
func (t *Task) SetMemCgIDFromCgroup(cg Cgroup) {
	for _, ctl := range cg.Controllers() {
		if ctl.Type() == CgroupControllerMemory {
			t.SetMemCgID(cg.ID())
			return
		}
	}
}

// ResetMemCgIDFromCgroup sets the memory cgroup id to zero, if the task has
// a memory cgroup.
func (t *Task) ResetMemCgIDFromCgroup(cg Cgroup) {
	for _, ctl := range cg.Controllers() {
		if ctl.Type() == CgroupControllerMemory {
			t.SetMemCgID(0)
			return
		}
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
	t.SetMemCgIDFromCgroup(c)
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
	t.SetMemCgID(0)
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
		log.Warningf("Cannot migrate to cgroup %v since task not currently in target hierarchy %v", dst, dst.HierarchyID())
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
	// Gather cgroups with t.mu held.
	t.mu.Lock()
	cgroups := make([]Cgroup, 0, len(t.cgroups))
	for c := range t.cgroups {
		cgroups = append(cgroups, c)
	}
	t.mu.Unlock()

	// Don't hold t.mu here as that can lead to lock inversion with
	// kernfs.ancestryRWMutex when calculating cgroup paths.
	cgEntries := make([]TaskCgroupEntry, 0, len(cgroups))
	for _, c := range cgroups {
		ctls := c.Controllers()
		ctlNames := make([]string, 0, len(ctls))

		// We're guaranteed to have a valid name, a non-empty controller list,
		// or both.

		// Explicit hierarchy name, if any.
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
