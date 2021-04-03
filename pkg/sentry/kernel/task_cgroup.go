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

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/syserror"
)

// EnterInitialCgroups moves t into an initial set of cgroups.
//
// Precondition: t isn't in any cgroups yet, t.cgs is empty.
//
// +checklocksignore parent.mu is conditionally acquired.
func (t *Task) EnterInitialCgroups(parent *Task) {
	var inherit map[Cgroup]struct{}
	if parent != nil {
		parent.mu.Lock()
		defer parent.mu.Unlock()
		inherit = parent.cgroups
	}
	joinSet := t.k.cgroupRegistry.computeInitialGroups(inherit)

	t.mu.Lock()
	defer t.mu.Unlock()
	// Transfer ownership of joinSet refs to the task's cgset.
	t.cgroups = joinSet
	for c, _ := range t.cgroups {
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

	for oldCG, _ := range t.cgroups {
		for _, oldCtl := range oldCG.Controllers() {
			if _, ok := newControllers[oldCtl.Type()]; ok {
				// Already in a cgroup with the same controller as one of the
				// new ones.  Requires migration between cgroups.
				//
				// TODO(b/183137098): Implement cgroup migration.
				log.Warningf("Cgroup migration is not implemented")
				return syserror.EBUSY
			}
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

// LeaveCgroups removes t out from all its cgroups.
func (t *Task) LeaveCgroups() {
	t.mu.Lock()
	defer t.mu.Unlock()
	for c, _ := range t.cgroups {
		t.leaveCgroupLocked(c)
	}
}

// +checklocks:t.mu
func (t *Task) leaveCgroupLocked(c Cgroup) {
	c.Leave(t)
	delete(t.cgroups, c)
	c.decRef()
}

// taskCgroupEntry represents a line in /proc/<pid>/cgroup, and is used to
// format a cgroup for display.
type taskCgroupEntry struct {
	hierarchyID uint32
	controllers string
	path        string
}

// GenerateProcTaskCgroup writes the contents of /proc/<pid>/cgroup for t to buf.
func (t *Task) GenerateProcTaskCgroup(buf *bytes.Buffer) {
	t.mu.Lock()
	defer t.mu.Unlock()

	cgEntries := make([]taskCgroupEntry, 0, len(t.cgroups))
	for c, _ := range t.cgroups {
		ctls := c.Controllers()
		ctlNames := make([]string, 0, len(ctls))
		for _, ctl := range ctls {
			ctlNames = append(ctlNames, string(ctl.Type()))
		}

		cgEntries = append(cgEntries, taskCgroupEntry{
			// Note: We're guaranteed to have at least one controller, and all
			// controllers are guaranteed to be on the same hierarchy.
			hierarchyID: ctls[0].HierarchyID(),
			controllers: strings.Join(ctlNames, ","),
			path:        c.Path(),
		})
	}

	sort.Slice(cgEntries, func(i, j int) bool { return cgEntries[i].hierarchyID > cgEntries[j].hierarchyID })
	for _, cgE := range cgEntries {
		fmt.Fprintf(buf, "%d:%s:%s\n", cgE.hierarchyID, cgE.controllers, cgE.path)
	}
}
