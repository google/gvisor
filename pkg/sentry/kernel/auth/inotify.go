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

package auth

// InotifyResource identifies a per-user inotify resource.
//
// +stateify savable
type InotifyResource int

const (
	// InotifyInstances counts file descriptions, including inherited and
	// duplicated descriptors only once.
	InotifyInstances InotifyResource = iota
	// InotifyWatches counts watches across all of a user's instances.
	InotifyWatches
)

// +stateify savable
type inotifyUsage struct {
	instances int32
	watches   int32
}

// InotifyLimit returns the limit for resource in ns.
func (ns *UserNamespace) InotifyLimit(resource InotifyResource) int32 {
	if resource == InotifyInstances {
		return ns.InotifyMaxInstances.Load()
	}
	return ns.InotifyMaxWatches.Load()
}

// SetInotifyLimit sets the limit for resource in ns. max must be non-negative.
func (ns *UserNamespace) SetInotifyLimit(resource InotifyResource, max int32) {
	if resource == InotifyInstances {
		ns.InotifyMaxInstances.Store(max)
	} else {
		ns.InotifyMaxWatches.Store(max)
	}
}

// IncInotify charges one resource to uid in ns and to each namespace's owner
// in its parent, as Linux's inc_ucount does. A failed charge is rolled back.
func (ns *UserNamespace) IncInotify(uid KUID, resource InotifyResource) bool {
	chargedUID := uid
	for cur := ns; cur != nil; cur = cur.parent {
		if !cur.tryIncInotify(chargedUID, resource) {
			for undo := ns; undo != cur; undo = undo.parent {
				undo.decInotify(uid, resource, 1)
				uid = undo.owner
			}
			return false
		}
		chargedUID = cur.owner
	}
	return true
}

func (ns *UserNamespace) tryIncInotify(uid KUID, resource InotifyResource) bool {
	ns.inotifyMu.Lock()
	defer ns.inotifyMu.Unlock()
	u := ns.inotifyUsers[uid]
	count := &u.watches
	if resource == InotifyInstances {
		count = &u.instances
	}
	if *count >= ns.InotifyLimit(resource) {
		return false
	}
	*count++
	if ns.inotifyUsers == nil {
		ns.inotifyUsers = make(map[KUID]inotifyUsage)
	}
	ns.inotifyUsers[uid] = u
	return true
}

// DecInotify releases n charges previously taken by IncInotify.
func (ns *UserNamespace) DecInotify(uid KUID, resource InotifyResource, n int32) {
	for cur := ns; cur != nil; cur = cur.parent {
		cur.decInotify(uid, resource, n)
		uid = cur.owner
	}
}

func (ns *UserNamespace) decInotify(uid KUID, resource InotifyResource, n int32) {
	ns.inotifyMu.Lock()
	defer ns.inotifyMu.Unlock()
	u := ns.inotifyUsers[uid]
	if resource == InotifyInstances {
		u.instances -= n
	} else {
		u.watches -= n
	}
	if u.instances < 0 || u.watches < 0 {
		panic("negative inotify resource count")
	}
	if u.instances == 0 && u.watches == 0 {
		delete(ns.inotifyUsers, uid)
	} else {
		ns.inotifyUsers[uid] = u
	}
}
