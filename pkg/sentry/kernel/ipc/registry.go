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
)

// Registry is similar to Object, but for registries. It represent an abstract
// SysV IPC registry with fields common to all SysV registries. Registry is not
// thread-safe, and should be protected using a mutex.
//
// +stateify savable
type Registry struct {
	// UserNS owning the IPC namespace this registry belongs to. Immutable.
	UserNS *auth.UserNamespace

	// objects is a map of IDs to IPC mechanisms.
	objects map[ID]Mechanism

	// KeysToIDs maps a lookup key to an ID.
	keysToIDs map[Key]ID

	// lastIDUsed is used to find the next available ID for object creation.
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

// Register adds the given object into Registry.Objects, and assigns it a new
// ID. It returns an error if all IDs are exhausted.
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

// ForAllObjects executes a given function for all given objects.
func (r *Registry) ForAllObjects(f func(o Mechanism)) {
	for _, o := range r.objects {
		f(o)
	}
}

// FindByID returns the mechanism with the given ID, nil if non exists.
func (r *Registry) FindByID(id ID) Mechanism {
	return r.objects[id]
}

// DissociateKey removes the association between a mechanism and its key
// (deletes it from r.keysToIDs), preventing it from being discovered by any new
// process, but not necessarily destroying it. If the given key doesn't exist,
// nothing is changed.
func (r *Registry) DissociateKey(key Key) {
	delete(r.keysToIDs, key)
}

// DissociateID removes the association between a mechanism and its ID (deletes
// it from r.objects). An ID can't be removed unless the associated key is
// removed already, this is done to prevent the users from acquiring nil a
// Mechanism.
//
// Precondition: must be preceded by a call to r.DissociateKey.
func (r *Registry) DissociateID(id ID) {
	delete(r.objects, id)
}

// ObjectCount returns the number of registered objects.
func (r *Registry) ObjectCount() int {
	return len(r.objects)
}

// LastIDUsed returns the last used ID.
func (r *Registry) LastIDUsed() ID {
	return r.lastIDUsed
}
