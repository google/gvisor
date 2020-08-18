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

package refs

import (
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sync"
)

type testCounter struct {
	AtomicRefCount

	// mu protects the boolean below.
	mu sync.Mutex

	// destroyed indicates whether this was destroyed.
	destroyed bool
}

func (t *testCounter) DecRef(ctx context.Context) {
	t.AtomicRefCount.DecRefWithDestructor(ctx, t.destroy)
}

func (t *testCounter) destroy(context.Context) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.destroyed = true
}

func (t *testCounter) IsDestroyed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.destroyed
}

func newTestCounter() *testCounter {
	return &testCounter{destroyed: false}
}

func TestOneRef(t *testing.T) {
	tc := newTestCounter()
	tc.DecRef(context.Background())

	if !tc.IsDestroyed() {
		t.Errorf("object should have been destroyed")
	}
}

func TestTwoRefs(t *testing.T) {
	tc := newTestCounter()
	tc.IncRef()
	ctx := context.Background()
	tc.DecRef(ctx)
	tc.DecRef(ctx)

	if !tc.IsDestroyed() {
		t.Errorf("object should have been destroyed")
	}
}

func TestMultiRefs(t *testing.T) {
	tc := newTestCounter()
	tc.IncRef()
	ctx := context.Background()
	tc.DecRef(ctx)

	tc.IncRef()
	tc.DecRef(ctx)

	tc.DecRef(ctx)

	if !tc.IsDestroyed() {
		t.Errorf("object should have been destroyed")
	}
}

func TestWeakRef(t *testing.T) {
	tc := newTestCounter()
	w := NewWeakRef(tc, nil)
	ctx := context.Background()

	// Try resolving.
	if x := w.Get(); x == nil {
		t.Errorf("weak reference didn't resolve: expected %v, got nil", tc)
	} else {
		x.DecRef(ctx)
	}

	// Try resolving again.
	if x := w.Get(); x == nil {
		t.Errorf("weak reference didn't resolve: expected %v, got nil", tc)
	} else {
		x.DecRef(ctx)
	}

	// Shouldn't be destroyed yet. (Can't continue if this fails.)
	if tc.IsDestroyed() {
		t.Fatalf("original object destroyed earlier than expected")
	}

	// Drop the original reference.
	tc.DecRef(ctx)

	// Assert destroyed.
	if !tc.IsDestroyed() {
		t.Errorf("original object not destroyed as expected")
	}

	// Shouldn't be anything.
	if x := w.Get(); x != nil {
		t.Errorf("weak reference resolved: expected nil, got %v", x)
	}
}

func TestWeakRefDrop(t *testing.T) {
	tc := newTestCounter()
	w := NewWeakRef(tc, nil)
	ctx := context.Background()
	w.Drop(ctx)

	// Just assert the list is empty.
	if !tc.weakRefs.Empty() {
		t.Errorf("weak reference not dropped")
	}

	// Drop the original reference.
	tc.DecRef(ctx)
}

type testWeakRefUser struct {
	weakRefGone func()
}

func (u *testWeakRefUser) WeakRefGone(ctx context.Context) {
	u.weakRefGone()
}

func TestCallback(t *testing.T) {
	called := false
	tc := newTestCounter()
	var w *WeakRef
	w = NewWeakRef(tc, &testWeakRefUser{func() {
		called = true

		// Check that the weak ref has been zapped.
		rc := w.obj.Load().(RefCounter)
		if v := reflect.ValueOf(rc); v != reflect.Zero(v.Type()) {
			t.Fatalf("Callback called with non-nil ptr")
		}

		// Check that we're not holding the mutex by acquiring and
		// releasing it.
		tc.mu.Lock()
		tc.mu.Unlock()
	}})

	// Drop the original reference, this must trigger the callback.
	ctx := context.Background()
	tc.DecRef(ctx)

	if !called {
		t.Fatalf("Callback not called")
	}
}
