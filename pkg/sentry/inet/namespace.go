// Copyright 2020 The gVisor Authors.
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

package inet

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/nsfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// Namespace represents a network namespace. See network_namespaces(7).
//
// +stateify savable
type Namespace struct {
	inode *nsfs.Inode

	// stack is the network stack implementation of this network namespace.
	stack Stack `state:"nosave"`

	// creator allows kernel to create new network stack for network namespaces.
	// If nil, no networking will function if network is namespaced.
	//
	// At afterLoad(), creator will be used to create network stack. Stateify
	// needs to wait for this field to be loaded before calling afterLoad().
	creator NetworkStackCreator `state:"wait"`

	// isRoot indicates whether this is the root network namespace.
	isRoot bool

	userNS *auth.UserNamespace

	// abstractSockets tracks abstract sockets that are in use.
	abstractSockets AbstractSocketNamespace
}

// NewRootNamespace creates the root network namespace, with creator
// allowing new network namespaces to be created. If creator is nil, no
// networking will function if the network is namespaced.
func NewRootNamespace(stack Stack, creator NetworkStackCreator, userNS *auth.UserNamespace) *Namespace {
	n := &Namespace{
		stack:   stack,
		creator: creator,
		isRoot:  true,
		userNS:  userNS,
	}
	n.abstractSockets.init()
	return n
}

// UserNamespace returns the user namespace associated with this namespace.
func (n *Namespace) UserNamespace() *auth.UserNamespace {
	return n.userNS
}

// SetInode sets the nsfs `inode` to the namespace.
func (n *Namespace) SetInode(inode *nsfs.Inode) {
	n.inode = inode
}

// GetInode returns the nsfs inode associated with this namespace.
func (n *Namespace) GetInode() *nsfs.Inode {
	return n.inode
}

// NewNamespace creates a new network namespace from the root.
func NewNamespace(root *Namespace, userNS *auth.UserNamespace) *Namespace {
	n := &Namespace{
		creator: root.creator,
		userNS:  userNS,
	}
	n.init()
	return n
}

// Destroy implements nsfs.Namespace.Destroy.
func (n *Namespace) Destroy(ctx context.Context) {
	if s := n.Stack(); s != nil {
		s.Destroy()
	}
}

// Type implements nsfs.Namespace.Type.
func (n *Namespace) Type() string {
	return "net"
}

// IncRef increments the Namespace's refcount.
func (n *Namespace) IncRef() {
	n.inode.IncRef()
}

// DecRef decrements the Namespace's refcount.
func (n *Namespace) DecRef(ctx context.Context) {
	n.inode.DecRef(ctx)
}

// Stack returns the network stack of n. Stack may return nil if no network
// stack is configured.
func (n *Namespace) Stack() Stack {
	return n.stack
}

// IsRoot returns whether n is the root network namespace.
func (n *Namespace) IsRoot() bool {
	return n.isRoot
}

// RestoreRootStack restores the root network namespace with stack. This should
// only be called when restoring kernel.
func (n *Namespace) RestoreRootStack(stack Stack) {
	if !n.isRoot {
		panic("RestoreRootStack can only be called on root network namespace")
	}
	if n.stack != nil {
		panic("RestoreRootStack called after a stack has already been set")
	}
	n.stack = stack
}

func (n *Namespace) init() {
	// Root network namespace will have stack assigned later.
	if n.isRoot {
		return
	}
	if n.creator != nil {
		var err error
		n.stack, err = n.creator.CreateStack()
		if err != nil {
			panic(err)
		}
	}
	n.abstractSockets.init()
}

// afterLoad is invoked by stateify.
func (n *Namespace) afterLoad() {
	n.init()
}

// AbstractSockets returns AbstractSocketNamespace.
func (n *Namespace) AbstractSockets() *AbstractSocketNamespace {
	return &n.abstractSockets
}

// NetworkStackCreator allows new instances of a network stack to be created. It
// is used by the kernel to create new network namespaces when requested.
type NetworkStackCreator interface {
	// CreateStack creates a new network stack for a network namespace.
	CreateStack() (Stack, error)
}
