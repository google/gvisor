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

package kernel

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/nsfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sync"
)

// UTSNamespace represents a UTS namespace, a holder of two system identifiers:
// the hostname and domain name.
//
// +stateify savable
type UTSNamespace struct {
	// mu protects all fields below.
	mu                sync.Mutex `state:"nosave"`
	hostName          string
	hostNameChanged   bool
	domainName        string
	domainNameChanged bool

	// userns is the user namespace associated with the UTSNamespace.
	// Privileged operations on this UTSNamespace must have appropriate
	// capabilities in userns.
	//
	// userns is immutable.
	userns *auth.UserNamespace

	inode *nsfs.Inode
}

// NewUTSNamespace creates a new UTS namespace.
func NewUTSNamespace(hostName, domainName string, userns *auth.UserNamespace) *UTSNamespace {
	return &UTSNamespace{
		hostName:   hostName,
		domainName: domainName,
		userns:     userns,
	}
}

// UTSNamespace returns the task's UTS namespace.
func (t *Task) UTSNamespace() *UTSNamespace {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.utsns
}

// GetUTSNamespace takes a reference on the task UTS namespace and
// returns it. It will return nil if the task isn't alive.
func (t *Task) GetUTSNamespace() *UTSNamespace {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.utsns != nil {
		t.utsns.IncRef()
	}
	return t.utsns
}

// HostName returns the host name of this UTS namespace.
func (u *UTSNamespace) HostName() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.hostName
}

// SetHostName sets the host name of this UTS namespace.
func (u *UTSNamespace) SetHostName(ctx context.Context, host string) {
	u.mu.Lock()
	u.hostName = host
	u.hostNameChanged = true
	u.mu.Unlock()

	KernelFromContext(ctx).HostNamePoller.Notify()
}

// DomainName returns the domain name of this UTS namespace.
func (u *UTSNamespace) DomainName() string {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.domainName
}

// SetDomainName sets the domain name of this UTS namespace.
func (u *UTSNamespace) SetDomainName(ctx context.Context, domain string) {
	u.mu.Lock()
	u.domainName = domain
	u.domainNameChanged = true
	u.mu.Unlock()

	KernelFromContext(ctx).DomainNamePoller.Notify()
}

// UserNamespace returns the user namespace associated with this UTS namespace.
func (u *UTSNamespace) UserNamespace() *auth.UserNamespace {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.userns
}

// Type implements nsfs.Namespace.Type.
func (u *UTSNamespace) Type() string {
	return "uts"
}

// Destroy implements nsfs.Namespace.Destroy.
func (u *UTSNamespace) Destroy(ctx context.Context) {}

// SetInode sets the nsfs `inode` to the UTS namespace.
func (u *UTSNamespace) SetInode(inode *nsfs.Inode) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.inode = inode
}

// GetInode returns the nsfs inode associated with the UTS  namespace.
func (u *UTSNamespace) GetInode() *nsfs.Inode {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.inode
}

// IncRef increments the Namespace's refcount.
func (u *UTSNamespace) IncRef() {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.inode.IncRef()
}

// DecRef decrements the namespace's refcount.
func (u *UTSNamespace) DecRef(ctx context.Context) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.inode.DecRef(ctx)
}

// Clone makes a copy of this UTS namespace, associating the given user
// namespace.
func (u *UTSNamespace) Clone(userns *auth.UserNamespace) *UTSNamespace {
	u.mu.Lock()
	defer u.mu.Unlock()
	return &UTSNamespace{
		hostName:          u.hostName,
		hostNameChanged:   u.hostNameChanged,
		domainName:        u.domainName,
		domainNameChanged: u.domainNameChanged,
		userns:            userns,
	}
}

// RestoreSpecValues updates the hostname and domainname if they haven't been
// explicitly set by the user.
func (u *UTSNamespace) RestoreSpecValues(hostName, domainName string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if !u.hostNameChanged {
		u.hostName = hostName
	}
	if !u.domainNameChanged {
		u.domainName = domainName
	}
}
