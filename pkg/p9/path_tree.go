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

package p9

import (
	"fmt"
	"sync"
)

// pathNode is a single node in a path traversal.
//
// These are shared by all fidRefs that point to the same path.
type pathNode struct {
	// fidRefName is a map[*fidRef]string mapping child fidRefs to their
	// path component name.
	fidRefNames sync.Map

	// childNodes is a map[string]*pathNode mapping child path component
	// names to their pathNode.
	childNodes sync.Map

	// mu does *not* protect the fields above.
	//
	// They are not synchronized because we allow certain operations (file
	// walk) to proceed without having to acquire a write lock. mu exists
	// to synchronize high-level, semantic operations, such as the
	// simultaneous creation and deletion of a file.
	mu sync.RWMutex
}

// pathNodeFor returns the path node for the given name, or a new one.
//
// Precondition: This call is synchronized w.r.t. other adding or removing of
// children.
func (p *pathNode) pathNodeFor(name string) *pathNode {
	// Load the existing path node.
	if pn, ok := p.childNodes.Load(name); ok {
		return pn.(*pathNode)
	}

	// Create a new pathNode for shared use.
	pn, _ := p.childNodes.LoadOrStore(name, new(pathNode))
	return pn.(*pathNode)
}

// nameFor returns the name for the given fidRef.
//
// Precondition: addChild is called for ref before nameFor.
func (p *pathNode) nameFor(ref *fidRef) string {
	if s, ok := p.fidRefNames.Load(ref); ok {
		return s.(string)
	}

	// This should not happen, don't proceed.
	panic(fmt.Sprintf("expected name for %+v, none found", ref))
}

// addChild adds a child to p.
//
// This applies only to an individual fidRef.
//
// Precondition: ref is added only once unless it is removed before adding with
// a new name.
func (p *pathNode) addChild(ref *fidRef, name string) {
	if s, ok := p.fidRefNames.Load(ref); ok {
		// This should not happen, don't proceed.
		panic(fmt.Sprintf("unexpected fidRef %+v with path %q, wanted %q", ref, s, name))
	}

	p.fidRefNames.Store(ref, name)
}

// removeChild removes the given child.
//
// This applies only to an individual fidRef.
func (p *pathNode) removeChild(ref *fidRef) {
	p.fidRefNames.Delete(ref)
}

// removeWithName removes all references with the given name.
//
// The original pathNode is returned by this function, and removed from this
// pathNode. Any operations on the removed tree must use this value.
//
// The provided function is executed after removal.
//
// Precondition: This call is synchronized w.r.t. other adding or removing of
// children.
func (p *pathNode) removeWithName(name string, fn func(ref *fidRef)) *pathNode {
	p.fidRefNames.Range(func(key, value interface{}) bool {
		if value.(string) == name {
			p.fidRefNames.Delete(key)
			fn(key.(*fidRef))
		}
		return true
	})

	// Return the original path node.
	origPathNode := p.pathNodeFor(name)
	p.childNodes.Delete(name)
	return origPathNode
}
