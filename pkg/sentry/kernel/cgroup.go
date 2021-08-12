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
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// InvalidCgroupHierarchyID indicates an uninitialized hierarchy ID.
const InvalidCgroupHierarchyID uint32 = 0

// CgroupControllerType is the name of a cgroup controller.
type CgroupControllerType string

// CgroupController is the common interface to cgroup controllers available to
// the entire sentry. The controllers themselves are defined by cgroupfs.
//
// Callers of this interface are often unable access synchronization needed to
// ensure returned values remain valid. Some of values returned from this
// interface are thus snapshots in time, and may become stale. This is ok for
// many callers like procfs.
type CgroupController interface {
	// Returns the type of this cgroup controller (ex "memory", "cpu"). Returned
	// value is valid for the lifetime of the controller.
	Type() CgroupControllerType

	// Hierarchy returns the ID of the hierarchy this cgroup controller is
	// attached to. Returned value is valid for the lifetime of the controller.
	HierarchyID() uint32

	// RootCgroup returns the root cgroup for this controller. Returned value is
	// valid for the lifetime of the controller.
	RootCgroup() Cgroup

	// NumCgroups returns the number of cgroups managed by this controller.
	// Returned value is a snapshot in time.
	NumCgroups() uint64

	// Enabled returns whether this controller is enabled. Returned value is a
	// snapshot in time.
	Enabled() bool
}

// Cgroup represents a named pointer to a cgroup in cgroupfs. When a task enters
// a cgroup, it holds a reference on the underlying dentry pointing to the
// cgroup.
//
// +stateify savable
type Cgroup struct {
	*kernfs.Dentry
	CgroupImpl
}

func (c *Cgroup) decRef() {
	c.Dentry.DecRef(context.Background())
}

// Path returns the absolute path of c, relative to its hierarchy root.
func (c *Cgroup) Path() string {
	return c.FSLocalPath()
}

// HierarchyID returns the id of the hierarchy that contains this cgroup.
func (c *Cgroup) HierarchyID() uint32 {
	// Note: a cgroup is guaranteed to have at least one controller.
	return c.Controllers()[0].HierarchyID()
}

// CgroupImpl is the common interface to cgroups.
type CgroupImpl interface {
	Controllers() []CgroupController
	Enter(t *Task)
	Leave(t *Task)
}

// hierarchy represents a cgroupfs filesystem instance, with a unique set of
// controllers attached to it. Multiple cgroupfs mounts may reference the same
// hierarchy.
//
// +stateify savable
type hierarchy struct {
	id uint32
	// These are a subset of the controllers in CgroupRegistry.controllers,
	// grouped here by hierarchy for conveninent lookup.
	controllers map[CgroupControllerType]CgroupController
	// fs is not owned by hierarchy. The FS is responsible for unregistering the
	// hierarchy on destruction, which removes this association.
	fs *vfs.Filesystem
}

func (h *hierarchy) match(ctypes []CgroupControllerType) bool {
	if len(ctypes) != len(h.controllers) {
		return false
	}
	for _, ty := range ctypes {
		if _, ok := h.controllers[ty]; !ok {
			return false
		}
	}
	return true
}

// cgroupFS is the public interface to cgroupfs. This lets the kernel package
// refer to cgroupfs.filesystem methods without directly depending on the
// cgroupfs package, which would lead to a circular dependency.
type cgroupFS interface {
	// Returns the vfs.Filesystem for the cgroupfs.
	VFSFilesystem() *vfs.Filesystem

	// InitializeHierarchyID sets the hierarchy ID for this filesystem during
	// filesystem creation. May only be called before the filesystem is visible
	// to the vfs layer.
	InitializeHierarchyID(hid uint32)
}

// CgroupRegistry tracks the active set of cgroup controllers on the system.
//
// +stateify savable
type CgroupRegistry struct {
	// lastHierarchyID is the id of the last allocated cgroup hierarchy. Valid
	// ids are from 1 to math.MaxUint32. Must be accessed through atomic ops.
	//
	lastHierarchyID uint32

	mu sync.Mutex `state:"nosave"`

	// controllers is the set of currently known cgroup controllers on the
	// system. Protected by mu.
	//
	// +checklocks:mu
	controllers map[CgroupControllerType]CgroupController

	// hierarchies is the active set of cgroup hierarchies. Protected by mu.
	//
	// +checklocks:mu
	hierarchies map[uint32]hierarchy
}

func newCgroupRegistry() *CgroupRegistry {
	return &CgroupRegistry{
		controllers: make(map[CgroupControllerType]CgroupController),
		hierarchies: make(map[uint32]hierarchy),
	}
}

// nextHierarchyID returns a newly allocated, unique hierarchy ID.
func (r *CgroupRegistry) nextHierarchyID() (uint32, error) {
	if hid := atomic.AddUint32(&r.lastHierarchyID, 1); hid != 0 {
		return hid, nil
	}
	return InvalidCgroupHierarchyID, fmt.Errorf("cgroup hierarchy ID overflow")
}

// FindHierarchy returns a cgroup filesystem containing exactly the set of
// controllers named in names. If no such FS is found, FindHierarchy return
// nil. FindHierarchy takes a reference on the returned FS, which is transferred
// to the caller.
func (r *CgroupRegistry) FindHierarchy(ctypes []CgroupControllerType) *vfs.Filesystem {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, h := range r.hierarchies {
		if h.match(ctypes) {
			if !h.fs.TryIncRef() {
				// Racing with filesystem destruction, namely h.fs.Release.
				// Since we hold r.mu, we know the hierarchy hasn't been
				// unregistered yet, but its associated filesystem is tearing
				// down.
				//
				// If we simply indicate the hierarchy wasn't found without
				// cleaning up the registry, the caller can race with the
				// unregister and find itself temporarily unable to create a new
				// hierarchy with a subset of the relevant controllers.
				//
				// To keep the result of FindHierarchy consistent with the
				// uniqueness of controllers enforced by Register, drop the
				// dying hierarchy now. The eventual unregister by the FS
				// teardown will become a no-op.
				r.unregisterLocked(h.id)
				return nil
			}
			return h.fs
		}
	}

	return nil
}

// Register registers the provided set of controllers with the registry as a new
// hierarchy. If any controller is already registered, the function returns an
// error without modifying the registry. Register sets the hierarchy ID for the
// filesystem on success.
func (r *CgroupRegistry) Register(cs []CgroupController, fs cgroupFS) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(cs) == 0 {
		return fmt.Errorf("can't register hierarchy with no controllers")
	}

	for _, c := range cs {
		if _, ok := r.controllers[c.Type()]; ok {
			return fmt.Errorf("controllers may only be mounted on a single hierarchy")
		}
	}

	hid, err := r.nextHierarchyID()
	if err != nil {
		return err
	}

	// Must not fail below here, once we publish the hierarchy ID.

	fs.InitializeHierarchyID(hid)

	h := hierarchy{
		id:          hid,
		controllers: make(map[CgroupControllerType]CgroupController),
		fs:          fs.VFSFilesystem(),
	}
	for _, c := range cs {
		n := c.Type()
		r.controllers[n] = c
		h.controllers[n] = c
	}
	r.hierarchies[hid] = h
	return nil
}

// Unregister removes a previously registered hierarchy from the registry. If no
// such hierarchy is registered, Unregister is a no-op.
func (r *CgroupRegistry) Unregister(hid uint32) {
	r.mu.Lock()
	r.unregisterLocked(hid)
	r.mu.Unlock()
}

// Precondition: Caller must hold r.mu.
// +checklocks:r.mu
func (r *CgroupRegistry) unregisterLocked(hid uint32) {
	if h, ok := r.hierarchies[hid]; ok {
		for name, _ := range h.controllers {
			delete(r.controllers, name)
		}
		delete(r.hierarchies, hid)
	}
}

// computeInitialGroups takes a reference on each of the returned cgroups. The
// caller takes ownership of this returned reference.
func (r *CgroupRegistry) computeInitialGroups(inherit map[Cgroup]struct{}) map[Cgroup]struct{} {
	r.mu.Lock()
	defer r.mu.Unlock()

	ctlSet := make(map[CgroupControllerType]CgroupController)
	cgset := make(map[Cgroup]struct{})

	// Remember controllers from the inherited cgroups set...
	for cg, _ := range inherit {
		cg.IncRef() // Ref transferred to caller.
		for _, ctl := range cg.Controllers() {
			ctlSet[ctl.Type()] = ctl
			cgset[cg] = struct{}{}
		}
	}

	// ... and add the root cgroups of all the missing controllers.
	for name, ctl := range r.controllers {
		if _, ok := ctlSet[name]; !ok {
			cg := ctl.RootCgroup()
			// Multiple controllers may share the same hierarchy, so may have
			// the same root cgroup. Grab a single ref per hierarchy root.
			if _, ok := cgset[cg]; ok {
				continue
			}
			cg.IncRef() // Ref transferred to caller.
			cgset[cg] = struct{}{}
		}
	}
	return cgset
}

// GenerateProcCgroups writes the contents of /proc/cgroups to buf.
func (r *CgroupRegistry) GenerateProcCgroups(buf *bytes.Buffer) {
	r.mu.Lock()
	entries := make([]string, 0, len(r.controllers))
	for _, c := range r.controllers {
		en := 0
		if c.Enabled() {
			en = 1
		}
		entries = append(entries, fmt.Sprintf("%s\t%d\t%d\t%d\n", c.Type(), c.HierarchyID(), c.NumCgroups(), en))
	}
	r.mu.Unlock()

	sort.Strings(entries)
	fmt.Fprint(buf, "#subsys_name\thierarchy\tnum_cgroups\tenabled\n")
	for _, e := range entries {
		fmt.Fprint(buf, e)
	}
}
