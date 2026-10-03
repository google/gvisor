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
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
)

// aliasDentry is a DentryImpl that shares its watch set with its hard link
// aliases.
type aliasDentry struct {
	vfsd    Dentry
	watches *Watches

	// onZeroWatches counts calls to OnZeroWatches.
	onZeroWatches int
}

func newAliasDentry(ws *Watches) *aliasDentry {
	d := &aliasDentry{watches: ws}
	d.vfsd.Init(d)
	return d
}

func (d *aliasDentry) IncRef()                                                      {}
func (d *aliasDentry) TryIncRef() bool                                              { return true }
func (d *aliasDentry) DecRef(context.Context)                                       {}
func (d *aliasDentry) InotifyWithParent(context.Context, uint32, uint32, EventType) {}
func (d *aliasDentry) Watches() *Watches                                            { return d.watches }
func (d *aliasDentry) OnZeroWatches(context.Context)                                { d.onZeroWatches++ }

func newInotifyForTest(id uint64) *Inotify {
	return &Inotify{
		id:      id,
		scratch: make([]byte, inotifyEventBaseSize),
		watches: make(map[int32]*Watch),
	}
}

// TestWatchesHasTarget verifies that HasTarget distinguishes dentries sharing
// a watch set.
func TestWatchesHasTarget(t *testing.T) {
	var ws Watches
	alias1 := newAliasDentry(&ws)
	alias2 := newAliasDentry(&ws)

	if ws.HasTarget(&alias1.vfsd) {
		t.Errorf("empty watch set: HasTarget(alias1) = true, want false")
	}

	w := &Watch{owner: newInotifyForTest(1), target: &alias1.vfsd}
	ws.Add(w)
	if !ws.HasTarget(&alias1.vfsd) {
		t.Errorf("watch on alias1: HasTarget(alias1) = false, want true")
	}
	if ws.HasTarget(&alias2.vfsd) {
		t.Errorf("watch on alias1: HasTarget(alias2) = true, want false")
	}

	ws.Remove(w.OwnerID())
	if ws.HasTarget(&alias1.vfsd) {
		t.Errorf("watch removed: HasTarget(alias1) = true, want false")
	}

	// HandleDeletion clears the whole set.
	ws.Add(&Watch{owner: newInotifyForTest(2), target: &alias1.vfsd})
	ws.HandleDeletion(context.Background())
	if ws.HasTarget(&alias1.vfsd) {
		t.Errorf("set deleted: HasTarget(alias1) = true, want false")
	}
}

// TestSharedWatchSetOnZeroWatches verifies that a dentry is released as soon
// as no watch targets it, even while the shared set is non-empty.
// See https://github.com/google/gvisor/issues/14619.
func TestSharedWatchSetOnZeroWatches(t *testing.T) {
	ctx := context.Background()
	var shared Watches
	alias1 := newAliasDentry(&shared)
	alias2 := newAliasDentry(&shared)

	i1 := newInotifyForTest(1)
	i2 := newInotifyForTest(2)
	wd1 := i1.AddWatch(&alias1.vfsd, linux.IN_ALL_EVENTS)
	i2.AddWatch(&alias2.vfsd, linux.IN_ALL_EVENTS)
	if got, want := shared.Size(), 2; got != want {
		t.Fatalf("shared.Size() = %d, want %d", got, want)
	}

	// alias1 is no longer a watch target, though the shared set is not empty.
	if err := i1.RmWatch(ctx, wd1); err != nil {
		t.Fatalf("RmWatch(wd1) failed: %v", err)
	}
	if got, want := alias1.onZeroWatches, 1; got != want {
		t.Errorf("after RmWatch on alias1: alias1.onZeroWatches = %d, want %d", got, want)
	}
	if got, want := alias2.onZeroWatches, 0; got != want {
		t.Errorf("after RmWatch on alias1: alias2.onZeroWatches = %d, want %d", got, want)
	}

	// Releasing the remaining instance releases alias2.
	i2.Release(ctx)
	if got, want := alias2.onZeroWatches, 1; got != want {
		t.Errorf("after Release of i2: alias2.onZeroWatches = %d, want %d", got, want)
	}
	if got, want := shared.Size(), 0; got != want {
		t.Errorf("shared.Size() = %d, want %d", got, want)
	}
}

// TestSharedWatchSetMultipleWatchers verifies that a dentry is not released
// while another watch still targets it.
func TestSharedWatchSetMultipleWatchers(t *testing.T) {
	ctx := context.Background()
	var shared Watches
	alias1 := newAliasDentry(&shared)

	i1 := newInotifyForTest(1)
	i2 := newInotifyForTest(2)
	wd1 := i1.AddWatch(&alias1.vfsd, linux.IN_ALL_EVENTS)
	i2.AddWatch(&alias1.vfsd, linux.IN_ALL_EVENTS)

	if err := i1.RmWatch(ctx, wd1); err != nil {
		t.Fatalf("RmWatch(wd1) failed: %v", err)
	}
	if got, want := alias1.onZeroWatches, 0; got != want {
		t.Errorf("i2 still watches alias1: alias1.onZeroWatches = %d, want %d", got, want)
	}

	i2.Release(ctx)
	if got, want := alias1.onZeroWatches, 1; got != want {
		t.Errorf("after Release of i2: alias1.onZeroWatches = %d, want %d", got, want)
	}
}

// TestSharedWatchSetDedupByOwner verifies that watching a second alias returns
// the first alias' descriptor and leaves the first alias as the target.
func TestSharedWatchSetDedupByOwner(t *testing.T) {
	ctx := context.Background()
	var shared Watches
	alias1 := newAliasDentry(&shared)
	alias2 := newAliasDentry(&shared)

	i := newInotifyForTest(1)
	wd1 := i.AddWatch(&alias1.vfsd, linux.IN_ALL_EVENTS)
	wd2 := i.AddWatch(&alias2.vfsd, linux.IN_ALL_EVENTS)
	if wd1 != wd2 {
		t.Errorf("AddWatch(alias2) = %d, want %d (same watch descriptor as alias1)", wd2, wd1)
	}
	if got, want := shared.Size(), 1; got != want {
		t.Errorf("shared.Size() = %d, want %d", got, want)
	}
	if !shared.HasTarget(&alias1.vfsd) {
		t.Errorf("HasTarget(alias1) = false, want true")
	}
	if shared.HasTarget(&alias2.vfsd) {
		t.Errorf("HasTarget(alias2) = true, want false")
	}

	i.Release(ctx)
	if got, want := alias1.onZeroWatches, 1; got != want {
		t.Errorf("after Release: alias1.onZeroWatches = %d, want %d", got, want)
	}
	if got, want := alias2.onZeroWatches, 0; got != want {
		t.Errorf("after Release: alias2.onZeroWatches = %d, want %d", got, want)
	}
}
