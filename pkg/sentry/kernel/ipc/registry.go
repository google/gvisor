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

package ipc

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/sync"
)

// Registry contains fields common to all SysV IPC registries.
//
// +stateify savable
type Registry struct {
	// Mu protects the ID and key maps and the allocation of new IDs.
	// Callers hold it across lookup, limit checks and registration to keep
	// mechanism-specific accounting consistent with these maps.
	Mu sync.Mutex `state:"nosave"`

	// UserNS owning the IPC namespace this registry belongs to. Immutable.
	UserNS *auth.UserNamespace

	// objects is a map of IDs to IPC mechanisms.
	//
	// +checklocks:Mu
	objects map[ID]Mechanism

	// keysToIDs maps a lookup key to an ID.
	//
	// +checklocks:Mu
	keysToIDs map[Key]ID

	// lastIDUsed is used to find the next available ID for object creation.
	//
	// +checklocks:Mu
	lastIDUsed ID
}

// NewRegistry return a new, initialized ipc.Registry.
func NewRegistry(userNS *auth.UserNamespace) *Registry {
	return &Registry{
		UserNS:    userNS,
		objects:   make(map[ID]Mechanism),
		keysToIDs: make(map[Key]ID),
	}
}

// Find uses key to search for and return a SysV mechanism. Find returns an
// error if an object is found by shouldn't be, or if the user doesn't have
// permission to use the object. If no object is found, Find checks create
// flag, and returns an error only if it's false.
//
// +checklocks:r.Mu
func (r *Registry) Find(ctx context.Context, key Key, mode linux.FileMode, create, exclusive bool) (Mechanism, error) {
	if id, ok := r.keysToIDs[key]; ok {
		mech := r.objects[id]
		mech.Lock()
		defer mech.Unlock()

		obj := mech.Object()
		creds := auth.CredentialsFromContext(ctx)
		if !obj.CheckPermissions(creds, vfs.AccessTypes(mode&linux.ModeOtherAll)) {
			// The [calling process / user] does not have permission to access
			// the set, and does not have the CAP_IPC_OWNER capability in the
			// user namespace that governs its IPC namespace.
			return nil, linuxerr.EACCES
		}

		if create && exclusive {
			// IPC_CREAT and IPC_EXCL were specified, but an object already
			// exists for key.
			return nil, linuxerr.EEXIST
		}
		return mech, nil
	}

	if !create {
		// No object exists for key and msgflg did not specify IPC_CREAT.
		return nil, linuxerr.ENOENT
	}

	return nil, nil
}

// Register adds m to r.objects, assigns it a new ID, and associates its key
// with that ID in r.keysToIDs. It returns an error if all IDs are exhausted.
//
// +checklocks:r.Mu
func (r *Registry) Register(m Mechanism) error {
	id, err := r.newID()
	if err != nil {
		return err
	}

	obj := m.Object()
	obj.ID = id

	r.objects[id] = m
	r.keysToIDs[obj.Key] = id

	return nil
}

// newID finds the first unused ID in the registry, and returns an error if
// non is found.
//
// +checklocks:r.Mu
func (r *Registry) newID() (ID, error) {
	// Find the next available ID.
	for id := r.lastIDUsed + 1; id != r.lastIDUsed; id++ {
		// Handle wrap around.
		if id < 0 {
			id = 0
			continue
		}
		if r.objects[id] == nil {
			r.lastIDUsed = id
			return id, nil
		}
	}

	log.Warningf("ids exhausted, they may be leaking")

	// The man pages for shmget(2) mention that ENOSPC should be used if "All
	// possible shared memory IDs have been taken (SHMMNI)". Other SysV
	// mechanisms don't have a specific errno for running out of IDs, but they
	// return ENOSPC if the max number of objects is exceeded, so we assume that
	// it's the same case.
	return 0, linuxerr.ENOSPC
}

// Remove removes the mechanism with the given id from the registry, and calls
// mechanism.Destroy to perform mechanism-specific removal.
//
// +checklocks:r.Mu
func (r *Registry) Remove(id ID, creds *auth.Credentials) error {
	mech := r.objects[id]
	if mech == nil {
		return linuxerr.EINVAL
	}

	mech.Lock()
	defer mech.Unlock()

	obj := mech.Object()

	// The effective user ID of the calling process must match the creator or
	// owner of the [mechanism], or the caller must be privileged.
	if !obj.CheckOwnership(creds) {
		return linuxerr.EPERM
	}

	delete(r.objects, obj.ID)
	delete(r.keysToIDs, obj.Key)
	mech.Destroy()

	return nil
}

// ForAllObjects calls f synchronously for each registered mechanism while the
// caller holds Mu. No reference is transferred.
// The registry lock does not protect mutable mechanism state. The callback
// must acquire the mechanism's mutex before accessing that state.
//
// The callback must return with Mu held and must not reacquire it. Retaining
// a mechanism requires a separate lifetime guarantee.
//
// +checklocks:r.Mu
func (r *Registry) ForAllObjects(f func(o Mechanism)) {
	for _, o := range r.objects {
		f(o)
	}
}

// FindByID returns the mechanism with the given ID, nil if non exists.
//
// +checklocks:r.Mu
func (r *Registry) FindByID(id ID) Mechanism {
	return r.objects[id]
}

// DissociateKey removes the association between a mechanism and its key from
// r.keysToIDs. Lookup by ID is unaffected, and the mechanism is not destroyed.
// If the given key doesn't exist, nothing is changed.
//
// +checklocks:r.Mu
func (r *Registry) DissociateKey(key Key) {
	delete(r.keysToIDs, key)
}

// DissociateID removes the association between a mechanism and its ID (deletes
// it from r.objects). An ID can't be removed unless the associated key is
// removed already, this is done to prevent the users from acquiring nil a
// Mechanism.
//
// Precondition: must be preceded by a call to r.DissociateKey.
//
// +checklocks:r.Mu
func (r *Registry) DissociateID(id ID) {
	delete(r.objects, id)
}

// ObjectCount returns the number of registered objects.
//
// +checklocks:r.Mu
func (r *Registry) ObjectCount() int {
	return len(r.objects)
}

// LastIDUsed returns the last used ID.
//
// +checklocks:r.Mu
func (r *Registry) LastIDUsed() ID {
	return r.lastIDUsed
}
