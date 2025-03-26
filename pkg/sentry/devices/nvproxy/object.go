// Copyright 2024 The gVisor Authors.
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

package nvproxy

import (
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/mm"
)

// object tracks a driver object.
//
// +stateify savable
type object struct {
	// These fields are initialized by nvproxy.objAdd() and are immutable thereafter.
	nvp    *nvproxy
	client *rootClient // may be == impl
	class  nvgpu.ClassID
	handle nvgpu.Handle // in client.resources, and also nvp.clients if impl is rootClient
	parent nvgpu.Handle
	impl   objectImpl

	// The driver tracks parent/child relationships and "arbitrary dependency"
	// relationships between objects separately; we treat parent/child
	// relationships as equivalent to other dependencies. These fields are
	// protected by client.objsMu.
	deps  map[*object]struct{} // objects that this object depends on
	rdeps map[*object]struct{} // objects that depend on this object
	objectFreeEntry
}

type objectImpl interface {
	// Object returns the object embedded in this objectImpl.
	Object() *object

	// Release is called when the driver object represented by this objectImpl
	// is freed. It may return a function that should be called after nvproxy
	// locks are released.
	//
	// Precondition: client.objsMu must be locked.
	Release(ctx context.Context) func()
}

// Object implements objectImpl.Object.
func (o *object) Object() *object {
	return o
}

// objAdd records the allocation of a driver object with class c and handle h,
// in the given client, represented by oi. Each non-zero handle in parentH and
// deps is a dependency of the created object, such that the freeing of any of
// those objects also results in the freeing of the recorded object.
//
// Precondition: client.objsMu must be locked.
func (nvp *nvproxy) objAdd(ctx context.Context, client *rootClient, h nvgpu.Handle, c nvgpu.ClassID, oi objectImpl, parentH nvgpu.Handle, deps ...nvgpu.Handle) {
	if h.Val == nvgpu.NV01_NULL_OBJECT {
		log.Traceback("nvproxy: new object (class %v) has invalid handle %v", c, h)
		return
	}

	o := oi.Object()
	o.nvp = nvp
	o.client = client
	o.class = c
	o.handle = h
	o.parent = parentH
	o.impl = oi
	if _, ok := client.resources[h]; ok {
		ctx.Warningf("nvproxy: handle %v:%v already in use", client.handle, h)
	}
	client.resources[h] = o

	if parentH.Val != nvgpu.NV01_NULL_OBJECT {
		parent, ok := client.resources[parentH]
		if !ok {
			log.Traceback("nvproxy: new object %v:%v (class %v) has invalid parent handle %v", client.handle, h, c, parentH)
		} else {
			objDep(o, parent)
		}
	}
	for _, depH := range deps {
		if depH.Val == nvgpu.NV01_NULL_OBJECT {
			continue
		}
		dep, ok := client.resources[depH]
		if !ok {
			log.Traceback("nvproxy: new object %v:%v (class %v) has invalid dependency handle %v", client.handle, h, c, depH)
			continue
		}
		objDep(o, dep)
	}

	if ctx.IsLogging(log.Debug) {
		ctx.Debugf("nvproxy: added object %v:%v (class %v) with parent %v, dependencies %v", client.handle, h, c, parentH, deps)
	}
}

// objAddDep records a dependency between the existing object with handle h1 on
// the existing object with handle h2, such that the freeing of the object with
// handle h2 results in the freeing of object h1. Both h1 and h2 are handles in
// the client c.
//
// Precondition: c.objsMu must be locked.
func (c *rootClient) objAddDep(h1, h2 nvgpu.Handle) {
	if h1.Val == 0 || h2.Val == 0 {
		return
	}
	if c == nil {
		log.Traceback("nvproxy: invalid client")
		return
	}
	o1, ok := c.resources[h1]
	if !ok {
		log.Traceback("nvproxy: invalid handle %v:%v", c.handle, h1)
		return
	}
	o2, ok := c.resources[h2]
	if !ok {
		log.Traceback("nvproxy: invalid handle %v:%v", c.handle, h2)
		return
	}
	objDep(o1, o2)
}

// Precondition: objsMu for clients of both o1 and o2 must be locked.
func objDep(o1, o2 *object) {
	if o1.deps == nil {
		o1.deps = make(map[*object]struct{})
	}
	o1.deps[o2] = struct{}{}
	if o2.rdeps == nil {
		o2.rdeps = make(map[*object]struct{})
	}
	o2.rdeps[o1] = struct{}{}
}

// objDup records the duplication of the driver object with handle srcH in the
// clientSrcH client, to handle dstH in the clientDst client, with
// new parent parentDstH.
//
// Precondition: clientDst.objsMu and clientSrc.objsMu must be locked.
func (nvp *nvproxy) objDup(ctx context.Context, clientDst, clientSrc *rootClient, dstH, parentDstH nvgpu.Handle, srcH nvgpu.Handle) {
	oSrc := clientSrc.getObject(ctx, srcH)
	if oSrc == nil {
		return
	}
	oDst := &miscObject{}
	nvp.objAdd(ctx, clientDst, dstH, oSrc.class, oDst, parentDstH)
	parentSrc := clientSrc.getObject(ctx, oSrc.parent)
	// Copy all non-parent dependencies.
	for dep := range oSrc.deps {
		if dep != parentSrc {
			objDep(oDst.Object(), dep)
		}
	}
}

// getClientWithLock returns the rootClient with the given handle.
//
// Postconditions:
// - rootClient.objsMu is locked, if client is non-nil
// - the caller must call the returned unlock function when done using client
func (nvp *nvproxy) getClientWithLock(ctx context.Context, clientH nvgpu.Handle) (*rootClient, func()) {
	nvp.clientsMu.RLock()
	client := nvp.clients[clientH]
	nvp.clientsMu.RUnlock()
	if client == nil {
		ctx.Warningf("nvproxy: failed to get client with unknown handle %v", clientH)
		return nil, nil
	}
	client.objsMu.Lock()
	if client.released {
		ctx.Warningf("nvproxy: client %v is already released", client.handle)
		client.objsMu.Unlock()
		return nil, nil
	}
	return client, client.objsMu.Unlock
}

// getClientsWithLock returns the rootClients with the given handles.
//
// Postconditions:
// - rootClient.objsMu is locked for both clients, if clients are non-nil
// - the caller must call the returned unlock function when done using clients
func (nvp *nvproxy) getClientsWithLock(ctx context.Context, clientH1, clientH2 nvgpu.Handle) (*rootClient, *rootClient, func()) {
	nvp.clientsMu.RLock()
	client1 := nvp.clients[clientH1]
	client2 := nvp.clients[clientH2]
	nvp.clientsMu.RUnlock()
	if client1 == nil || client2 == nil {
		ctx.Warningf("nvproxy: failed to get clients with unknown handles %v (%p) and %v (%p)", clientH1, client1, clientH2, client2)
		return nil, nil, nil
	}
	// To avoid deadlock, choose locking order based on the numerical values of
	// client handles. This is similar to what the driver does in
	// src/nvidia/src/libraries/resserv/src/rs_server.c:_serverLockDualClientWithLockInfo().
	var unlock func()
	if client1 == client2 {
		client1.objsMu.Lock()
		unlock = client1.objsMu.Unlock
	} else if client1.handle.Val < client2.handle.Val {
		client1.objsMu.Lock()
		client2.objsMu.Lock()
		unlock = func() {
			client2.objsMu.Unlock()
			client1.objsMu.Unlock()
		}
	} else {
		client2.objsMu.Lock()
		client1.objsMu.Lock()
		unlock = func() {
			client1.objsMu.Unlock()
			client2.objsMu.Unlock()
		}
	}
	if client1.released || client2.released {
		ctx.Warningf("nvproxy: client %v or %v is already released", client1.handle, client2.handle)
		unlock()
		return nil, nil, nil
	}
	return client1, client2, unlock
}

// objFree marks an object and its transitive dependents as freed. It returns
// a list of functions that must be called after nvproxy locks are released.
//
// Compare
// src/nvidia/src/libraries/resserv/src/rs_server.c:serverFreeResourceTree().
//
// Precondition: client.objsMu must be locked.
func (nvp *nvproxy) objFree(ctx context.Context, client *rootClient, h nvgpu.Handle) []func() {
	// Check for recursive calls to objFree() (via objectImpl.Release()).
	// serverFreeResourceTree() permits this; we currently don't for
	// simplicity.
	if !client.objsFreeList.Empty() {
		panic("nvproxy.objFree called with non-empty free list (possible recursion?)")
	}

	o, ok := client.resources[h]
	if !ok {
		// When RS_COMPATABILITY_MODE is defined as true in the driver (as it
		// is in Linux), the driver permits NV_ESC_RM_FREE on nonexistent
		// handles as a no-op, and applications do this, so log at level INFO
		// rather than WARNING.
		ctx.Infof("nvproxy: freeing object with unknown handle %v:%v", client.handle, h)
		return nil
	}
	if client.objsFreeSet == nil {
		client.objsFreeSet = make(map[*object]struct{})
	}
	client.prependFreedLockedRecursive(o)
	var deferReleases []func()
	for !client.objsFreeList.Empty() {
		o2 := client.objsFreeList.Front()
		deferRelease := o2.impl.Release(ctx)
		if deferRelease != nil {
			deferReleases = append(deferReleases, deferRelease)
		}
		for o3 := range o2.deps {
			delete(o3.rdeps, o2)
		}
		delete(o2.client.resources, o2.handle)
		client.objsFreeList.Remove(o2)
		delete(client.objsFreeSet, o2)
		if ctx.IsLogging(log.Debug) {
			ctx.Debugf("nvproxy: freed object %v:%v (class %v)", o2.client.handle, o2.handle, o2.class)
		}
	}
	return deferReleases
}

// Precondition: c.objsMu must be locked.
func (c *rootClient) prependFreedLockedRecursive(o *object) {
	if _, ok := c.objsFreeSet[o]; ok {
		// o is already on the free list; move it to the front so that it
		// remains freed before our caller's o.
		c.objsFreeList.Remove(o)
	} else {
		c.objsFreeSet[o] = struct{}{}
	}
	c.objsFreeList.PushFront(o)

	// In the driver, freeing an object causes its children and dependents to
	// be freed first; see
	// src/nvidia/src/libraries/resserv/src/rs_server.c:serverFreeResourceTree()
	// => clientUpdatePendingFreeList_IMPL(). Replicate this freeing order.
	for o2 := range o.rdeps {
		c.prependFreedLockedRecursive(o2)
	}
}

// +stateify savable
type capturedRmAllocParams struct {
	fd              *frontendFD
	ioctlParams     nvgpu.NVOS64_PARAMETERS
	rightsRequested nvgpu.RS_ACCESS_MASK
	allocParams     []byte
}

func captureRmAllocParams[Params any](fd *frontendFD, ioctlParams *nvgpu.NVOS64_PARAMETERS, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *Params) capturedRmAllocParams {
	var allocParamsBuf []byte
	if allocParams != nil {
		if allocParamsMarshal, ok := any(allocParams).(marshal.Marshallable); ok {
			allocParamsBuf = make([]byte, allocParamsMarshal.SizeBytes())
			allocParamsMarshal.MarshalBytes(allocParamsBuf)
		} else {
			log.Traceback("nvproxy: allocParams %T is not marshalable")
		}
	}
	return capturedRmAllocParams{
		fd:              fd,
		ioctlParams:     *ioctlParams,
		rightsRequested: rightsRequested,
		allocParams:     allocParamsBuf,
	}
}

// rmAllocObject is an objectImpl tracking a driver object allocated by an
// invocation of NV_ESC_RM_ALLOC whose class is not represented by a more
// specific type.
//
// +stateify savable
type rmAllocObject struct {
	object

	params capturedRmAllocParams
}

func newRmAllocObject[Params any](fd *frontendFD, ioctlParams *nvgpu.NVOS64_PARAMETERS, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *Params) *rmAllocObject {
	return &rmAllocObject{
		params: captureRmAllocParams(fd, ioctlParams, rightsRequested, allocParams),
	}
}

// Release implements objectImpl.Release.
func (o *rmAllocObject) Release(ctx context.Context) func() {
	// no-op
	return nil
}

// miscObject is an objectImpl tracking a driver object allocated by something
// other than an invocation of NV_ESC_RM_ALLOC, whose class is not represented
// by a more specific type.
type miscObject struct {
	object
}

// Release implements objectImpl.Release.
func (o *miscObject) Release(ctx context.Context) func() {
	// no-op
	return nil
}

// rootClient is an objectImpl tracking a NV01_ROOT_CLIENT.
//
// +stateify savable
type rootClient struct {
	object

	objsMu objsMutex `state:"nosave"`
	// These fields are protected by objsMu.
	objsFreeList objectFreeList       `state:"nosave"`
	objsFreeSet  map[*object]struct{} `state:"nosave"`
	resources    map[nvgpu.Handle]*object
	released     bool

	params capturedRmAllocParams
}

func newRootClient[Params any](fd *frontendFD, ioctlParams *nvgpu.NVOS64_PARAMETERS, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *Params) *rootClient {
	return &rootClient{
		resources: make(map[nvgpu.Handle]*object),
		params:    captureRmAllocParams(fd, ioctlParams, rightsRequested, allocParams),
	}
}

// Release implements objectImpl.Release.
func (c *rootClient) Release(ctx context.Context) func() {
	c.released = true
	c.nvp.clientsMu.Lock()
	defer c.nvp.clientsMu.Unlock()
	delete(c.params.fd.clients, c)
	delete(c.nvp.clients, c.handle)
	return nil
}

// Precondition: c.objsMu must be locked.
func (c *rootClient) getObject(ctx context.Context, h nvgpu.Handle) *object {
	o := c.resources[h]
	if o == nil {
		ctx.Warningf("nvproxy: failed to get object with unknown handle %v:%v", c.handle, h)
	}
	return o
}

// osDescMem is an objectImpl tracking a NV01_MEMORY_SYSTEM_OS_DESCRIPTOR.
type osDescMem struct {
	object
	pinnedRanges []mm.PinnedRange

	// If m is non-zero, it is the start address of a mapping of length len
	// that should be unmapped when the osDescMem is released.
	m   uintptr
	len uintptr
}

// Release implements objectImpl.Release.
func (o *osDescMem) Release(ctx context.Context) func() {
	// Unpin pages (which takes MM locks) without holding nvproxy locks.
	return func() {
		if o.m != 0 {
			if _, _, errno := unix.RawSyscall(unix.SYS_MUNMAP, o.m, o.len, 0); errno != 0 {
				ctx.Warningf("nvproxy: failed to unmap %#x-%#x: %v", o.m, o.m+o.len, errno)
			}
		}
		mm.Unpin(o.pinnedRanges)
		if ctx.IsLogging(log.Debug) {
			total := uint64(0)
			for _, pr := range o.pinnedRanges {
				total += uint64(pr.Source.Length())
			}
			ctx.Debugf("nvproxy: unpinned %d bytes for released OS descriptor", total)
		}
	}
}
