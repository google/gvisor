// Copyright 2018 The gVisor Authors.
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

// Package refs defines an interface for reference counted objects. It
// also provides a drop-in implementation called AtomicRefCount.
package refs

import (
	"reflect"
	"sync"
	"sync/atomic"
)

// RefCounter is the interface to be implemented by objects that are reference
// counted.
type RefCounter interface {
	// IncRef increments the reference counter on the object.
	IncRef()

	// DecRef decrements the reference counter on the object.
	//
	// Note that AtomicRefCounter.DecRef() does not support destructors.
	// If a type has a destructor, it must implement its own DecRef()
	// method and call AtomicRefCounter.DecRefWithDestructor(destructor).
	DecRef()

	// TryIncRef attempts to increase the reference counter on the object,
	// but may fail if all references have already been dropped. This
	// should be used only in special circumstances, such as WeakRefs.
	TryIncRef() bool

	// addWeakRef adds the given weak reference. Note that you should have a
	// reference to the object when calling this method.
	addWeakRef(*WeakRef)

	// dropWeakRef drops the given weak reference. Note that you should have
	// a reference to the object when calling this method.
	dropWeakRef(*WeakRef)
}

// A WeakRefUser is notified when the last non-weak reference is dropped.
type WeakRefUser interface {
	// WeakRefGone is called when the last non-weak reference is dropped.
	WeakRefGone()
}

// WeakRef is a weak reference.
//
// +stateify savable
type WeakRef struct {
	weakRefEntry `state:"nosave"`

	// obj is an atomic value that points to the refCounter.
	obj atomic.Value `state:".(savedReference)"`

	// user is notified when the weak ref is zapped by the object getting
	// destroyed.
	user WeakRefUser
}

// weakRefPool is a pool of weak references to avoid allocations on the hot path.
var weakRefPool = sync.Pool{
	New: func() interface{} {
		return &WeakRef{}
	},
}

// NewWeakRef acquires a weak reference for the given object.
//
// An optional user will be notified when the last non-weak reference is
// dropped.
//
// Note that you must hold a reference to the object prior to getting a weak
// reference. (But you may drop the non-weak reference after that.)
func NewWeakRef(rc RefCounter, u WeakRefUser) *WeakRef {
	w := weakRefPool.Get().(*WeakRef)
	w.init(rc, u)
	return w
}

// get attempts to get a normal reference to the underlying object, and returns
// the object. If this weak reference has already been zapped (the object has
// been destroyed) then false is returned. If the object still exists, then
// true is returned.
func (w *WeakRef) get() (RefCounter, bool) {
	rc := w.obj.Load().(RefCounter)
	if v := reflect.ValueOf(rc); v == reflect.Zero(v.Type()) {
		// This pointer has already been zapped by zap() below. We do
		// this to ensure that the GC can collect the underlying
		// RefCounter objects and they don't hog resources.
		return nil, false
	}
	if !rc.TryIncRef() {
		return nil, true
	}
	return rc, true
}

// Get attempts to get a normal reference to the underlying object, and returns
// the object. If this fails (the object no longer exists), then nil will be
// returned instead.
func (w *WeakRef) Get() RefCounter {
	rc, _ := w.get()
	return rc
}

// Drop drops this weak reference. You should always call drop when you are
// finished with the weak reference. You may not use this object after calling
// drop.
func (w *WeakRef) Drop() {
	rc, ok := w.get()
	if !ok {
		// We've been zapped already. When the refcounter has called
		// zap, we're guaranteed it's not holding references.
		weakRefPool.Put(w)
		return
	}
	if rc == nil {
		// The object is in the process of being destroyed. We can't
		// remove this from the object's list, nor can we return this
		// object to the pool. It'll just be garbage collected. This is
		// a rare edge case, so it's not a big deal.
		return
	}

	// At this point, we have a reference on the object. So destruction
	// of the object (and zapping this weak reference) can't race here.
	rc.dropWeakRef(w)

	// And now aren't on the object's list of weak references. So it won't
	// zap us if this causes the reference count to drop to zero.
	rc.DecRef()

	// Return to the pool.
	weakRefPool.Put(w)
}

// init initializes this weak reference.
func (w *WeakRef) init(rc RefCounter, u WeakRefUser) {
	// Reset the contents of the weak reference.
	// This is important because we are reseting the atomic value type.
	// Otherwise, we could panic here if obj is different than what it was
	// the last time this was used.
	*w = WeakRef{}
	w.user = u
	w.obj.Store(rc)

	// In the load path, we may already have a nil value. So we need to
	// check whether or not that is the case before calling addWeakRef.
	if v := reflect.ValueOf(rc); v != reflect.Zero(v.Type()) {
		rc.addWeakRef(w)
	}
}

// zap zaps this weak reference.
func (w *WeakRef) zap() {
	// We need to be careful about types here.
	// So reflect is involved. But it's not that bad.
	rc := w.obj.Load()
	typ := reflect.TypeOf(rc)
	w.obj.Store(reflect.Zero(typ).Interface())
}

// AtomicRefCount keeps a reference count using atomic operations and calls the
// destructor when the count reaches zero.
//
// N.B. To allow the zero-object to be initialized, the count is offset by
//      1, that is, when refCount is n, there are really n+1 references.
//
// +stateify savable
type AtomicRefCount struct {
	// refCount is composed of two fields:
	//
	//	[32-bit speculative references]:[32-bit real references]
	//
	// Speculative references are used for TryIncRef, to avoid a
	// CompareAndSwap loop. See IncRef, DecRef and TryIncRef for details of
	// how these fields are used.
	refCount int64

	// mu protects the list below.
	mu sync.Mutex `state:"nosave"`

	// weakRefs is our collection of weak references.
	weakRefs weakRefList `state:"nosave"`
}

// ReadRefs returns the current number of references. The returned count is
// inherently racy and is unsafe to use without external synchronization.
func (r *AtomicRefCount) ReadRefs() int64 {
	// Account for the internal -1 offset on refcounts.
	return atomic.LoadInt64(&r.refCount) + 1
}

// IncRef increments this object's reference count. While the count is kept
// greater than zero, the destructor doesn't get called.
//
// The sanity check here is limited to real references, since if they have
// dropped beneath zero then the object should have been destroyed.
func (r *AtomicRefCount) IncRef() {
	if v := atomic.AddInt64(&r.refCount, 1); v <= 0 {
		panic("Incrementing non-positive ref count")
	}
}

// TryIncRef attempts to increment the reference count, *unless the count has
// already reached zero*. If false is returned, then the object has already
// been destroyed, and the weak reference is no longer valid. If true if
// returned then a valid reference is now held on the object.
//
// To do this safely without a loop, a speculative reference is first acquired
// on the object. This allows multiple concurrent TryIncRef calls to
// distinguish other TryIncRef calls from genuine references held.
func (r *AtomicRefCount) TryIncRef() bool {
	const speculativeRef = 1 << 32
	v := atomic.AddInt64(&r.refCount, speculativeRef)
	if int32(v) < 0 {
		// This object has already been freed.
		atomic.AddInt64(&r.refCount, -speculativeRef)
		return false
	}

	// Turn into a real reference.
	atomic.AddInt64(&r.refCount, -speculativeRef+1)
	return true
}

// addWeakRef adds the given weak reference.
func (r *AtomicRefCount) addWeakRef(w *WeakRef) {
	r.mu.Lock()
	r.weakRefs.PushBack(w)
	r.mu.Unlock()
}

// dropWeakRef drops the given weak reference.
func (r *AtomicRefCount) dropWeakRef(w *WeakRef) {
	r.mu.Lock()
	r.weakRefs.Remove(w)
	r.mu.Unlock()
}

// DecRefWithDestructor decrements the object's reference count. If the
// resulting count is negative and the destructor is not nil, then the
// destructor will be called.
//
// Note that speculative references are counted here. Since they were added
// prior to real references reaching zero, they will successfully convert to
// real references. In other words, we see speculative references only in the
// following case:
//
//	A: TryIncRef [speculative increase => sees non-negative references]
//	B: DecRef [real decrease]
//	A: TryIncRef [transform speculative to real]
//
func (r *AtomicRefCount) DecRefWithDestructor(destroy func()) {
	switch v := atomic.AddInt64(&r.refCount, -1); {
	case v < -1:
		panic("Decrementing non-positive ref count")

	case v == -1:
		// Zap weak references. Note that at this point, all weak
		// references are already invalid. That is, TryIncRef() will
		// return false due to the reference count check.
		r.mu.Lock()
		for !r.weakRefs.Empty() {
			w := r.weakRefs.Front()
			// Capture the callback because w cannot be touched
			// after it's zapped -- the owner is free it reuse it
			// after that.
			user := w.user
			r.weakRefs.Remove(w)
			w.zap()

			if user != nil {
				r.mu.Unlock()
				user.WeakRefGone()
				r.mu.Lock()
			}
		}
		r.mu.Unlock()

		// Call the destructor.
		if destroy != nil {
			destroy()
		}
	}
}

// DecRef decrements this object's reference count.
func (r *AtomicRefCount) DecRef() {
	r.DecRefWithDestructor(nil)
}
