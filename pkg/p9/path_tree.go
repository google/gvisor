// Copyright 2018 Google LLC
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

package p9

import (
	"fmt"
	"sync"
)

// pathNode is a single node in a path traversal.
//
// These are shared by all fidRefs that point to the same path.
//
// These are not synchronized because we allow certain operations (file walk)
// to proceed without having to acquire a write lock. The lock in this
// structure exists to synchronize high-level, semantic operations, such as the
// simultaneous creation and deletion of a file.
//
// (+) below is the path component string.
type pathNode struct {
	mu       sync.RWMutex // See above.
	fidRefs  sync.Map     // => map[*fidRef]string(+)
	children sync.Map     // => map[string(+)]*pathNode
	count    int64
}

// pathNodeFor returns the path node for the given name, or a new one.
//
// Precondition: mu must be held in a readable fashion.
func (p *pathNode) pathNodeFor(name string) *pathNode {
	// Load the existing path node.
	if pn, ok := p.children.Load(name); ok {
		return pn.(*pathNode)
	}

	// Create a new pathNode for shared use.
	pn, _ := p.children.LoadOrStore(name, new(pathNode))
	return pn.(*pathNode)
}

// nameFor returns the name for the given fidRef.
//
// Precondition: mu must be held in a readable fashion.
func (p *pathNode) nameFor(ref *fidRef) string {
	if s, ok := p.fidRefs.Load(ref); ok {
		return s.(string)
	}

	// This should not happen, don't proceed.
	panic(fmt.Sprintf("expected name for %+v, none found", ref))
}

// addChild adds a child to the given pathNode.
//
// This applies only to an individual fidRef.
//
// Precondition: mu must be held in a writable fashion.
func (p *pathNode) addChild(ref *fidRef, name string) {
	if s, ok := p.fidRefs.Load(ref); ok {
		// This should not happen, don't proceed.
		panic(fmt.Sprintf("unexpected fidRef %+v with path %q, wanted %q", ref, s, name))
	}

	p.fidRefs.Store(ref, name)
}

// removeChild removes the given child.
//
// This applies only to an individual fidRef.
//
// Precondition: mu must be held in a writable fashion.
func (p *pathNode) removeChild(ref *fidRef) {
	p.fidRefs.Delete(ref)
}

// removeWithName removes all references with the given name.
//
// The original pathNode is returned by this function, and removed from this
// pathNode. Any operations on the removed tree must use this value.
//
// The provided function is executed after removal.
//
// Precondition: mu must be held in a writable fashion.
func (p *pathNode) removeWithName(name string, fn func(ref *fidRef)) *pathNode {
	p.fidRefs.Range(func(key, value interface{}) bool {
		if value.(string) == name {
			p.fidRefs.Delete(key)
			fn(key.(*fidRef))
		}
		return true
	})

	// Return the original path node.
	origPathNode := p.pathNodeFor(name)
	p.children.Delete(name)
	return origPathNode
}
