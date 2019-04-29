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
	"sync"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/refs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/socket/unix/transport"
)

// +stateify savable
type abstractEndpoint struct {
	ep   transport.BoundEndpoint
	wr   *refs.WeakRef
	name string
	ns   *AbstractSocketNamespace
}

// WeakRefGone implements refs.WeakRefUser.WeakRefGone.
func (e *abstractEndpoint) WeakRefGone() {
	e.ns.mu.Lock()
	if e.ns.endpoints[e.name].ep == e.ep {
		delete(e.ns.endpoints, e.name)
	}
	e.ns.mu.Unlock()
}

// AbstractSocketNamespace is used to implement the Linux abstract socket functionality.
//
// +stateify savable
type AbstractSocketNamespace struct {
	mu sync.Mutex `state:"nosave"`

	// Keeps mapping from name to endpoint.
	endpoints map[string]abstractEndpoint
}

// NewAbstractSocketNamespace returns a new AbstractSocketNamespace.
func NewAbstractSocketNamespace() *AbstractSocketNamespace {
	return &AbstractSocketNamespace{
		endpoints: make(map[string]abstractEndpoint),
	}
}

// A boundEndpoint wraps a transport.BoundEndpoint to maintain a reference on
// its backing object.
type boundEndpoint struct {
	transport.BoundEndpoint
	rc refs.RefCounter
}

// Release implements transport.BoundEndpoint.Release.
func (e *boundEndpoint) Release() {
	e.rc.DecRef()
	e.BoundEndpoint.Release()
}

// BoundEndpoint retrieves the endpoint bound to the given name. The return
// value is nil if no endpoint was bound.
func (a *AbstractSocketNamespace) BoundEndpoint(name string) transport.BoundEndpoint {
	a.mu.Lock()
	defer a.mu.Unlock()

	ep, ok := a.endpoints[name]
	if !ok {
		return nil
	}

	rc := ep.wr.Get()
	if rc == nil {
		delete(a.endpoints, name)
		return nil
	}

	return &boundEndpoint{ep.ep, rc}
}

// Bind binds the given socket.
//
// When the last reference managed by rc is dropped, ep may be removed from the
// namespace.
func (a *AbstractSocketNamespace) Bind(name string, ep transport.BoundEndpoint, rc refs.RefCounter) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if ep, ok := a.endpoints[name]; ok {
		if rc := ep.wr.Get(); rc != nil {
			rc.DecRef()
			return syscall.EADDRINUSE
		}
	}

	ae := abstractEndpoint{ep: ep, name: name, ns: a}
	ae.wr = refs.NewWeakRef(rc, &ae)
	a.endpoints[name] = ae
	return nil
}
