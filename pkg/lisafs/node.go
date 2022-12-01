// Copyright 2022 The gVisor Authors.
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

package lisafs

import (
	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sync"
)

// numStaticChildren is the number of static children tracked by each node.
// Sampling certain filesystem heavy workloads showed that a majority of
// directories store at most 5 children in their map. This should be kept low
// to minimize the memory overhead for each node. 5 is fairly low and at the
// same time helps avoid map allocations for majority of nodes. Benchmarking
// also showed that static arrays are faster than maps for lookups until n=8.
const numStaticChildren = 5

// Node is a node on the filesystem tree. A Node is shared by all the
// ControlFDs opened on that position. For a given Server, there will only be
// one Node for a given filesystem position.
//
// Reference Model:
//   - Each node holds a ref on its parent for its entire lifetime.
type Node struct {
	// node's ref count is protected by its parent's childrenMu.
	nodeRefs

	// opMu synchronizes high level operations on this path.
	//
	// It is used to ensure the following which are important for security:
	//	* This node's data is protected by opMu. So all operations that change its
	//   data should hold opMu for writing. For example: write, setstat, setxattr,
	//   etc. This entails that if this node represents a directory, creation and
	//   deletion operations happening directly under this directory must lock
	//   opMu for writing. All operations accessing data must hold opMu for
	//   reading. This is to avoid the can of worms that open when creation and
	//   deletion are allowed to race. This prevents any walks from occurring
	//   during creation or deletion.
	//	* When this node is being deleted, the deletion handler must hold opMu for
	//   writing. This ensures that there are no concurrent operations going on
	//   this node while it is being deleted and potentially being replaced with
	//   something hazardous.
	//
	// A useful consequence of the above is that holding opMu for reading
	// guarantees that the Server can not change Nodes on the path until this
	// Node. For instance, if the grandparent needs to be renamed or deleted,
	// the client must first delete this node to avoid ENOTEMPTY error. Deleting
	// this node is not possible while opMu is read locked.
	opMu sync.RWMutex

	// deleted indicates whether the backing file has been unlinked. This can be
	// used to deny operations on FDs on this Node after deletion because it is
	// not safe for FD implementations to do host walks up to this position
	// anymore. This node may have been replaced with something hazardous.
	// deleted is protected by opMu. deleted must only be accessed/mutated using
	// atomics; see markDeletedRecursive for more details.
	deleted atomicbitops.Uint32

	// name is the name of the file represented by this Node in parent. If this
	// FD represents the root directory, then name is an empty string. name is
	// protected by the backing server's rename mutex.
	name string

	// parent is this parent node which tracks this node as a child. parent is
	// protected by the backing server's rename mutex.
	parent *Node

	// controlFDs is a linked list of all the ControlFDs opened on this node.
	// Prefer this over a slice to avoid additional allocations. Each ControlFD
	// is an implicit linked list node so there are no additional allocations
	// needed to maintain the linked list.
	controlFDsMu sync.Mutex
	controlFDs   controlFDList

	// Here is a performance hack. Past experience has shown that map allocations
	// on each node for tracking children costs a lot of memory. More small
	// allocations also fragment memory. To save allocations, statically track
	// upto numStaticChildren children using hardcoded pointers. If more children
	// are inserted then move to a map. Use dynamicChildren iff it is non-nil.

	// The folowing fields are protected by childrenMu.
	childrenMu     sync.Mutex
	staticChildren [numStaticChildren]struct {
		name string
		node *Node
	}
	dynamicChildren map[string]*Node
}

// DecRef implements refs.RefCounter.DecRef. Note that the context
// parameter should never be used. It exists solely to comply with the
// refs.RefCounter interface.
//
// Precondition: server's rename mutex must be at least read locked.
func (n *Node) DecRef(context.Context) {
	if n.parent == nil {
		n.nodeRefs.DecRef(nil)
		return
	}
	// If this is the only ref on node then it will need to be destroyed.
	n.parent.childrenMu.Lock()
	deleted := false
	n.nodeRefs.DecRef(func() {
		n.parent.removeChildLocked(n.name)
		deleted = true
	})
	n.parent.childrenMu.Unlock()
	if deleted {
		// Drop ref on parent. Keep Decref call lock free for scalability.
		n.parent.DecRef(nil)
	}
}

// InitLocked must be called before first use of fd.
//
// Precondition: parent.childrenMu is locked.
//
// Postconditions: A ref on n is transferred to the caller.
func (n *Node) InitLocked(name string, parent *Node) {
	n.nodeRefs.InitRefs()
	n.name = name
	n.parent = parent
	if parent != nil {
		parent.IncRef()
		parent.insertChildLocked(name, n)
	}
}

// LookupChildLocked looks up for a child with given name. Returns nil if child
// does not exist.
//
// Preconditions: childrenMu is locked.
func (n *Node) LookupChildLocked(name string) *Node {
	if n.dynamicChildren != nil {
		return n.dynamicChildren[name]
	}

	for i := 0; i < numStaticChildren; i++ {
		if n.staticChildren[i].name == name {
			return n.staticChildren[i].node
		}
	}
	return nil
}

// WithChildrenMu executes fn with n.childrenMu locked.
func (n *Node) WithChildrenMu(fn func()) {
	n.childrenMu.Lock()
	defer n.childrenMu.Unlock()
	fn()
}

// FilePath returns the absolute path of the backing file. This is an expensive
// operation. The returned path should be free of any intermediate symlinks
// because all internal (non-leaf) nodes are directories.
//
// Precondition:
//   - server's rename mutex must be at least read locked. Calling handlers must
//     at least have read concurrency guarantee from the server.
func (n *Node) FilePath() string {
	// Walk upwards and prepend name to res.
	var res fspath.Builder
	for n.parent != nil {
		res.PrependComponent(n.name)
		n = n.parent
	}
	// n is the root node.
	res.PrependByte('/')
	return res.String()
}

func (n *Node) isDeleted() bool {
	return n.deleted.Load() != 0
}

func (n *Node) removeFD(fd *ControlFD) {
	n.controlFDsMu.Lock()
	defer n.controlFDsMu.Unlock()
	n.controlFDs.Remove(fd)
}

func (n *Node) insertFD(fd *ControlFD) {
	n.controlFDsMu.Lock()
	defer n.controlFDsMu.Unlock()
	n.controlFDs.PushBack(fd)
}

func (n *Node) forEachFD(fn func(*ControlFD)) {
	n.controlFDsMu.Lock()
	defer n.controlFDsMu.Unlock()
	for fd := n.controlFDs.Front(); fd != nil; fd = fd.Next() {
		fn(fd)
	}
}

// removeChildLocked removes child with given name from n and returns the
// removed child. Returns nil if no such child existed.
//
// Precondition: childrenMu is locked.
func (n *Node) removeChildLocked(name string) *Node {
	if n.dynamicChildren != nil {
		toRemove := n.dynamicChildren[name]
		delete(n.dynamicChildren, name)
		return toRemove
	}

	for i := 0; i < numStaticChildren; i++ {
		if n.staticChildren[i].name == name {
			toRemove := n.staticChildren[i].node
			n.staticChildren[i].name = ""
			n.staticChildren[i].node = nil
			return toRemove
		}
	}
	return nil
}

// insertChildLocked inserts child into n. It does not check for duplicates.
//
// Precondition: childrenMu is locked.
func (n *Node) insertChildLocked(name string, child *Node) {
	// Try to insert statically first if staticChildren is still being used.
	if n.dynamicChildren == nil {
		for i := 0; i < numStaticChildren; i++ {
			if n.staticChildren[i].node == nil {
				n.staticChildren[i].node = child
				n.staticChildren[i].name = name
				return
			}
		}

		// Ran out of static space. Need to start inserting dynamically.
		// Shift everything to the map.
		n.dynamicChildren = make(map[string]*Node)
		for i := 0; i < numStaticChildren; i++ {
			// From above loop we know all staticChildren entries are non-nil.
			n.dynamicChildren[n.staticChildren[i].name] = n.staticChildren[i].node
			n.staticChildren[i].name = ""
			n.staticChildren[i].node = nil
		}
	}

	n.dynamicChildren[name] = child
}

func (n *Node) forEachChild(fn func(*Node)) {
	n.childrenMu.Lock()
	defer n.childrenMu.Unlock()

	if n.dynamicChildren != nil {
		for _, child := range n.dynamicChildren {
			fn(child)
		}
		return
	}

	for i := 0; i < numStaticChildren; i++ {
		if n.staticChildren[i].node != nil {
			fn(n.staticChildren[i].node)
		}
	}
}

// Precondition: opMu must be locked for writing on the root node being marked
// as deleted.
func (n *Node) markDeletedRecursive() {
	n.deleted.Store(1)

	// No need to hold opMu for children as it introduces lock ordering issues
	// because forEachChild locks childrenMu. Locking opMu after childrenMu
	// violates the lock ordering. Anyway if a directory is being deleted, it
	// must not have children. The client must have already deleted the entire
	// subtree. If the client did not delete this subtree nodes, then the subtree
	// was deleted externally and there is not much we can do. This is best
	// effort work to mark the subtree as deleted.
	n.forEachChild(func(child *Node) {
		child.markDeletedRecursive()
	})
}
