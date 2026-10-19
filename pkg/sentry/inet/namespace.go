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
	goContext "context"
	"slices"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/nsfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/tcpip"
)

// Namespace represents a network namespace. See network_namespaces(7).
//
// +stateify savable
type Namespace struct {
	inode *nsfs.Inode

	// stack is the network stack implementation of this network namespace.
	stack Stack

	// creator allows kernel to create new network stack for network namespaces.
	// If nil, no networking will function if network is namespaced.
	//
	// At afterLoad(), creator will be used to create network stack. Stateify
	// needs to wait for this field to be loaded before calling afterLoad().
	creator NetworkStackCreator `state:"wait"`

	// isRoot indicates whether this is the root network namespace.
	isRoot bool

	// root is the root network namespace. Only set for non-root namespaces.
	root *Namespace

	// childrenMu protects children. Only used on the root network namespace.
	childrenMu sync.Mutex `state:"nosave"`

	// children tracks active non-root network namespaces in creation order.
	// +checklocks:childrenMu
	children []*Namespace

	userNS *auth.UserNamespace

	// abstractSockets tracks abstract sockets that are in use.
	abstractSockets AbstractSocketNamespace

	// netlinkMcastTable manages multicast group membership for netlink sockets.
	netlinkMcastTable *McastTable
}

// NewRootNamespace creates the root network namespace, with creator
// allowing new network namespaces to be created. If creator is nil, no
// networking will function if the network is namespaced.
func NewRootNamespace(stack Stack, creator NetworkStackCreator, userNS *auth.UserNamespace) *Namespace {
	n := &Namespace{
		stack:             stack,
		creator:           creator,
		isRoot:            true,
		userNS:            userNS,
		netlinkMcastTable: NewNetlinkMcastTable(),
	}
	if eventPublishingStack, ok := stack.(InterfaceEventPublisher); ok {
		eventPublishingStack.AddInterfaceEventSubscriber(n.netlinkMcastTable)
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
func NewNamespace(parent *Namespace, userNS *auth.UserNamespace) *Namespace {
	root := parent
	if !root.isRoot {
		root = parent.root
	}
	n := &Namespace{
		root:              root,
		creator:           parent.creator,
		userNS:            userNS,
		netlinkMcastTable: NewNetlinkMcastTable(),
	}
	n.init()
	if root != nil {
		root.childrenMu.Lock()
		root.children = append(root.children, n)
		root.childrenMu.Unlock()
	}
	return n
}

// Destroy implements nsfs.Namespace.Destroy.
func (n *Namespace) Destroy(ctx context.Context) {
	if n.root != nil {
		n.root.childrenMu.Lock()
		n.root.children = slices.DeleteFunc(n.root.children, func(c *Namespace) bool {
			return c == n
		})
		n.root.childrenMu.Unlock()
	}
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

// ResetStack resets the stack in the network namespace to nil. This should
// only be called when restoring kernel.
func (n *Namespace) ResetStack() {
	n.stack = nil
}

func (n *Namespace) init() {
	if n.abstractSockets.endpoints == nil {
		n.abstractSockets.init()
	}
	// Root network namespace will have stack assigned later.
	if n.isRoot || n.stack != nil || n.creator == nil {
		return
	}
	var err error
	n.stack, err = n.creator.CreateStack()
	if err != nil {
		panic(err)
	}
	n.stack.SetPreserveAllNICs(true)
	if eventPublishingStack, ok := n.stack.(InterfaceEventPublisher); ok {
		eventPublishingStack.AddInterfaceEventSubscriber(n.netlinkMcastTable)
	}
}

// afterLoad is invoked by stateify.
func (n *Namespace) afterLoad(goContext.Context) {
	n.init()
}

func (n *Namespace) allStacks() []Stack {
	var stacks []Stack
	if n.stack != nil {
		stacks = append(stacks, n.stack)
	}
	n.childrenMu.Lock()
	for _, child := range n.children {
		if s := child.Stack(); s != nil {
			stacks = append(stacks, s)
		}
	}
	n.childrenMu.Unlock()
	return stacks
}

// SetRemoveConfStacks sets removeConf on the root network namespace stack and
// all child network namespace stacks.
func (n *Namespace) SetRemoveConfStacks(removeConf bool) {
	for _, s := range n.allStacks() {
		s.SetRemoveConf(removeConf)
	}
}

// PauseStacks pauses the root network namespace stack and all child network
// namespace stacks.
func (n *Namespace) PauseStacks() {
	for _, s := range n.allStacks() {
		s.Pause()
	}
}

// ResumeStacks resumes the root network namespace stack and all child network
// namespace stacks.
func (n *Namespace) ResumeStacks() {
	for _, s := range n.allStacks() {
		s.Resume()
	}
}

// RestoreStacks restores the root network namespace stack and all child
// network namespace stacks after checkpoint load.
func (n *Namespace) RestoreStacks() {
	stacks := n.allStacks()
	for _, s := range stacks {
		s.RestoreNICsAndEndpoints()
	}
	tcpip.AsyncLoading.Wait()
	for _, s := range stacks {
		s.StartTransportProtocols()
	}
}

// AbstractSockets returns AbstractSocketNamespace.
func (n *Namespace) AbstractSockets() *AbstractSocketNamespace {
	return &n.abstractSockets
}

// NetlinkMcastTable returns the netlink multicast group table.
func (n *Namespace) NetlinkMcastTable() *McastTable {
	return n.netlinkMcastTable
}

// HasCapability checks if ctx has the given capability with respect to the network namespace n.
func (n *Namespace) HasCapability(ctx context.Context, cp linux.Capability) bool {
	creds := auth.CredentialsFromContext(ctx)
	return creds.HasCapabilityIn(cp, n.userNS)
}

// NetworkStackCreator allows new instances of a network stack to be created. It
// is used by the kernel to create new network namespaces when requested.
type NetworkStackCreator interface {
	// CreateStack creates a new network stack for a network namespace.
	CreateStack() (Stack, error)
}
