// Copyright 2026 The gVisor Authors.
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

package vfs

import (
	goContext "context"
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sync"
)

// LandlockObject is the file a Landlock rule refers to. A rule matches a file
// exactly when the file's slot holds the rule's Landlock object. E.g. a rule
// added via /a/dir keeps matching after "mv /a/dir /b/dir", since the file
// keeps its slot, and so its Landlock object.
//
// A Landlock object holds a reference on the Dentry it was created for, which
// keeps the file's slot alive, as Linux's get_inode_object() ihold()s the
// inode. It is released when the last ruleset or domain holding it is, or
// detached earlier when its Filesystem is destroyed, as in Linux's
// hook_sb_delete(). Either way it is never reused: a later rule for the file
// gets a new Landlock object.
//
// Matches Linux [security/landlock/object.h]:struct landlock_object
//
// +stateify savable
type LandlockObject struct {
	// refs is the number of rulesets and domains with a rule for the Landlock
	// object. refs is accessed using atomic memory operations.
	refs atomicbitops.Int64

	// slot is the slot the Landlock object was created in. slot is immutable.
	slot *LandlockObjectSlot

	// fs is the Filesystem that dentry belongs to, on which the Landlock
	// object is registered for detachment. fs is immutable.
	fs *Filesystem

	// dentry is the Dentry the Landlock object holds a reference on, or nil
	// once the object has been released or detached. dentry is protected by
	// slot.mu.
	dentry *Dentry
}

// IncRef increments o's reference count.
//
// Preconditions: The caller holds a reference on o.
func (o *LandlockObject) IncRef() {
	if o.refs.Add(1) <= 1 {
		panic(fmt.Sprintf("LandlockObject %p: IncRef without a reference", o))
	}
}

// tryIncRef increments o's reference count if it is not zero, and returns
// whether it did.
//
// Matches Linux [security/landlock/fs.c]:get_inode_object() calling
// refcount_inc_not_zero().
func (o *LandlockObject) tryIncRef() bool {
	for {
		r := o.refs.Load()
		if r <= 0 {
			return false
		}
		if o.refs.CompareAndSwap(r, r+1) {
			return true
		}
	}
}

// DecRef decrements o's reference count, releasing o when it reaches zero.
//
// Matches Linux [security/landlock/object.c]:landlock_put_object()
func (o *LandlockObject) DecRef(ctx context.Context) {
	switch r := o.refs.Add(-1); {
	case r == 0:
		o.release(ctx)
	case r < 0:
		panic(fmt.Sprintf("LandlockObject %p: DecRef with no references", o))
	}
}

// release detaches o from its file once no rule refers to it.
//
// Matches Linux [security/landlock/fs.c]:release_inode()
func (o *LandlockObject) release(ctx context.Context) {
	if o.detach(ctx) {
		o.fs.unregisterLandlockObject(o)
	}
}

// detach empties o's slot if it still holds o and drops o's reference on its
// Dentry. It returns false if o was already detached.
func (o *LandlockObject) detach(ctx context.Context) bool {
	s := o.slot
	s.mu.Lock()
	if s.object.Load() == o {
		s.object.Store(nil)
	}
	d := o.dentry
	o.dentry = nil
	s.mu.Unlock()
	if d == nil {
		return false
	}
	d.DecRef(ctx)
	if s.owner != nil {
		s.owner.LandlockObjectSlotReleased(s)
	}
	return true
}

// LandlockObjectSlot holds the Landlock object of one file. Filesystems embed
// it in per-file state that every Dentry for the file shares, e.g. a tmpfs
// inode, so that hard links share it, as Linux keeps the Landlock object in
// the inode's LSM blob.
//
// The zero value is an empty slot, ready for use.
//
// Matches Linux [security/landlock/fs.h]:struct landlock_inode_security
//
// +stateify savable
type LandlockObjectSlot struct {
	// mu serializes the creation of a Landlock object in the slot with its
	// release, and protects the dentry field of the object the slot holds.
	mu sync.Mutex `state:"nosave"`

	// object is the Landlock object for the file, or nil if no rule refers to
	// it. object may be loaded without holding mu, and is stored with mu held.
	object atomic.Pointer[LandlockObject] `state:".(*LandlockObject)"`

	// owner, if not nil, is told when the slot becomes empty. owner is
	// immutable.
	owner LandlockObjectSlotOwner
}

// LandlockObjectSlotOwner is implemented by filesystems that have no per-file
// state to embed slots in, e.g. overlay and FUSE, and instead keep slots in a
// table of their own, from which an empty slot must be removed.
type LandlockObjectSlotOwner interface {
	// LandlockObjectSlotReleased is called, with no locks held, after the
	// Landlock object in slot is released or detached. The owner must recheck
	// that slot is still empty under the lock it creates Landlock objects with.
	LandlockObjectSlotReleased(slot *LandlockObjectSlot)
}

// NewLandlockObjectSlot returns a new empty slot owned by owner.
func NewLandlockObjectSlot(owner LandlockObjectSlotOwner) *LandlockObjectSlot {
	return &LandlockObjectSlot{owner: owner}
}

// saveObject is called by stateify.
func (s *LandlockObjectSlot) saveObject() *LandlockObject {
	return s.object.Load()
}

// loadObject is called by stateify.
func (s *LandlockObjectSlot) loadObject(_ goContext.Context, o *LandlockObject) {
	s.object.Store(o)
}

// Object returns the Landlock object in s, or nil if s is nil or empty.
func (s *LandlockObjectSlot) Object() *LandlockObject {
	if s == nil {
		return nil
	}
	return s.object.Load()
}

// IsEmpty returns whether s holds no Landlock object.
func (s *LandlockObjectSlot) IsEmpty() bool {
	return s.object.Load() == nil
}

// GetObject returns the Landlock object in s with a new reference, first
// creating it for d, a Dentry on fs using s as its slot, if s is empty.
//
// Preconditions: The caller holds a reference on d.
//
// Matches Linux [security/landlock/fs.c]:get_inode_object()
func (s *LandlockObjectSlot) GetObject(fs *Filesystem, d *Dentry) (*LandlockObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if o := s.object.Load(); o != nil && o.tryIncRef() {
		return o, nil
	}
	// Either s is empty, or its Landlock object's last reference is being
	// dropped and its release is waiting on s.mu. In the latter case the
	// object is replaced, and its release leaves s alone.
	d.IncRef()
	o := &LandlockObject{
		slot:   s,
		fs:     fs,
		dentry: d,
	}
	o.refs.Store(1)
	fs.registerLandlockObject(o)
	s.object.Store(o)
	return o, nil
}

// LandlockObjectGetter is an optional interface implemented by DentryImpls
// whose slots are created under a lock of the FilesystemImpl's own; see
// LandlockObjectSlotOwner.
type LandlockObjectGetter interface {
	// GetLandlockObject is as GetLandlockObject for the Dentry, which is on
	// fs.
	GetLandlockObject(fs *Filesystem) (*LandlockObject, error)
}

// GetLandlockObject returns the Landlock object for the file vd names with a
// new reference, creating it if no rule refers to the file yet. It returns
// EBADFD if the file's filesystem cannot name it.
//
// Preconditions: The caller holds a reference on vd.
func GetLandlockObject(vd VirtualDentry) (*LandlockObject, error) {
	fs := vd.mount.fs
	if g, ok := vd.dentry.impl.(LandlockObjectGetter); ok {
		return g.GetLandlockObject(fs)
	}
	s := vd.dentry.impl.LandlockObjectSlot()
	if s == nil {
		return nil, linuxerr.EBADFD
	}
	return s.GetObject(fs, vd.dentry)
}

// landlockObject returns the Landlock object currently in d's slot, or nil if
// no rule refers to d's file or d's filesystem cannot name it.
func (d *Dentry) landlockObject() *LandlockObject {
	return d.impl.LandlockObjectSlot().Object()
}

// registerLandlockObject records that o holds a reference on a Dentry of fs.
func (fs *Filesystem) registerLandlockObject(o *LandlockObject) {
	fs.landlockObjectsMu.Lock()
	defer fs.landlockObjectsMu.Unlock()
	if fs.landlockObjects == nil {
		fs.landlockObjects = make(map[*LandlockObject]struct{})
	}
	fs.landlockObjects[o] = struct{}{}
}

// unregisterLandlockObject reverses registerLandlockObject.
func (fs *Filesystem) unregisterLandlockObject(o *LandlockObject) {
	fs.landlockObjectsMu.Lock()
	defer fs.landlockObjectsMu.Unlock()
	delete(fs.landlockObjects, o)
}

// detachLandlockObjects detaches every Landlock object registered on fs for
// which detachIf returns true, or every one if detachIf is nil. Rules for a
// detached Landlock object stay in their rulesets and domains and match
// nothing.
//
// Matches Linux [security/landlock/fs.c]:hook_sb_delete()
func (fs *Filesystem) detachLandlockObjects(ctx context.Context, detachIf func(*Dentry) bool) {
	// Landlock objects are registered with their slot's mu held, so the
	// slot's mu cannot be taken with fs.landlockObjectsMu held.
	fs.landlockObjectsMu.Lock()
	objects := make([]*LandlockObject, 0, len(fs.landlockObjects))
	for o := range fs.landlockObjects {
		objects = append(objects, o)
	}
	fs.landlockObjectsMu.Unlock()
	for _, o := range objects {
		if detachIf != nil {
			o.slot.mu.Lock()
			d := o.dentry
			o.slot.mu.Unlock()
			if d != nil && !detachIf(d) {
				continue
			}
		}
		o.detach(ctx)
		fs.unregisterLandlockObject(o)
	}
}

// detachDeadLandlockObjects detaches fs's Landlock objects with a dead Dentry,
// e.g. a rule on a since-deleted file, so that a checkpoint need not save the
// Dentry. Such a rule could only still match through a surviving hard link,
// and stops matching after restore.
func (fs *Filesystem) detachDeadLandlockObjects(ctx context.Context) {
	fs.detachLandlockObjects(ctx, func(d *Dentry) bool { return d.IsDead() })
}

// LandlockSlotTable is a copy-on-write map from a LandlockObjectSlotOwner's
// keys to its slots, e.g. FUSE node IDs. Lookups take no lock, since a
// Landlock check makes one for every ancestor it walks; updates are made with
// the owner's lock held. A nil map is an empty table.
type LandlockSlotTable[K comparable] = atomic.Pointer[map[K]*LandlockObjectSlot]

// LookupLandlockSlot returns the slot for key in t, or nil.
func LookupLandlockSlot[K comparable](t *LandlockSlotTable[K], key K) *LandlockObjectSlot {
	if m := t.Load(); m != nil {
		return (*m)[key]
	}
	return nil
}

// StoreLandlockSlot maps key to slot in t.
//
// Preconditions: The caller holds the lock serializing updates to t.
func StoreLandlockSlot[K comparable](t *LandlockSlotTable[K], key K, slot *LandlockObjectSlot) {
	var old map[K]*LandlockObjectSlot
	if m := t.Load(); m != nil {
		old = *m
	}
	m := make(map[K]*LandlockObjectSlot, len(old)+1)
	for k, s := range old {
		m[k] = s
	}
	m[key] = slot
	t.Store(&m)
}

// DeleteLandlockSlot removes every key mapped to slot from t if slot is
// empty. E.g. overlay maps both the lower and upper file of a copied-up file
// to one slot.
//
// Preconditions: The caller holds the lock serializing updates to t.
func DeleteLandlockSlot[K comparable](t *LandlockSlotTable[K], slot *LandlockObjectSlot) {
	old := t.Load()
	if old == nil || !slot.IsEmpty() {
		return
	}
	m := make(map[K]*LandlockObjectSlot, len(*old))
	for k, s := range *old {
		if s != slot {
			m[k] = s
		}
	}
	if len(m) == 0 {
		t.Store(nil)
		return
	}
	t.Store(&m)
}
