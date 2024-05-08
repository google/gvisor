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
	impl   objectImpl

	// The driver tracks parent/child relationships and "arbitrary dependency"
	// relationships between objects separately; we treat parent/child
	// relationships as equivalent to other dependencies. These fields are
	// protected by nvp.objsMu.
	deps  map[*object]struct{} // objects that this object depends on
	rdeps map[*object]struct{} // objects that depend on this object
	objectFreeEntry
}

type objectImpl interface {
	// Object returns the object embedded in this objectImpl.
	Object() *object

	// Release is called when the driver object represented by this objectImpl
	// is freed.
	//
	// Preconditions: nvproxy.objsMu must be locked.
	Release(ctx context.Context)
}

// Object implements objectImpl.Object.
func (o *object) Object() *object {
	return o
}

func (nvp *nvproxy) objsLock() {
	nvp.objsMu.Lock()
}

func (nvp *nvproxy) objsUnlock() {
	cleanup := nvp.objsCleanup
	nvp.objsCleanup = nil
	nvp.objsMu.Unlock()
	for _, f := range cleanup {
		f()
	}
}

// objAdd records the allocation of a driver object with class c and handle h,
// in the client with handle clientH, represented by oi. Each non-zero handle
// in deps is a dependency of the created object, such that the freeing of any
// of those objects also results in the freeing of the recorded object.
func (nvp *nvproxy) objAdd(ctx context.Context, clientH, h nvgpu.Handle, c nvgpu.ClassID, oi objectImpl, deps ...nvgpu.Handle) {
	if h.Val == 0 {
		log.Traceback("nvproxy: new object (class %v) has invalid handle 0", c)
		return
	}
	var client *rootClient
	// The driver forced NV01_ROOT and NV01_ROOT_NON_PRIV to NV01_ROOT_CLIENT,
	// so we only need to check for the latter.
	if c == nvgpu.NV01_ROOT_CLIENT {
		clientH = h
		client = oi.(*rootClient)
		if _, ok := nvp.clients[h]; ok {
			ctx.Warningf("nvproxy: client handle %v already in use", h)
		}
		nvp.clients[h] = client
	} else {
		var ok bool
		client, ok = nvp.clients[clientH]
		if !ok {
			log.Traceback("nvproxy: new object %v (class %v) has invalid client handle %v", h, c, clientH)
			return
		}
	}
	o := oi.Object()
	o.nvp = nvp
	o.client = client
	o.class = c
	o.handle = h
	o.impl = oi
	if _, ok := client.resources[h]; ok {
		ctx.Warningf("nvproxy: handle %v:%v already in use", clientH, h)
	}
	client.resources[h] = o
	for _, depH := range deps {
		if depH.Val == 0 /* aka NV01_NULL_OBJECT */ {
			continue
		}
		dep, ok := client.resources[depH]
		if !ok {
			log.Traceback("nvproxy: new object %v:%v (class %v) has invalid dependency handle %v", clientH, h, c, depH)
			continue
		}
		nvp.objDep(o, dep)
	}
	if ctx.IsLogging(log.Debug) {
		ctx.Debugf("nvproxy: added object %v:%v (class %v) with dependencies %v", clientH, h, c, deps)
	}
}

// objAddDep records a dependency between the existing object with handle h1 on
// the existing object with handle h2, such that the freeing of the object with
// handle h2 results in the freeing of object h1. Both h1 and h2 are handles in
// the client with handle clientH.
func (nvp *nvproxy) objAddDep(clientH, h1, h2 nvgpu.Handle) {
	if h1.Val == 0 || h2.Val == 0 {
		return
	}
	client, ok := nvp.clients[clientH]
	if !ok {
		log.Traceback("nvproxy: invalid client handle %v", clientH)
		return
	}
	o1, ok := client.resources[h1]
	if !ok {
		log.Traceback("nvproxy: invalid handle %v:%v", clientH, h1)
		return
	}
	o2, ok := client.resources[h2]
	if !ok {
		log.Traceback("nvproxy: invalid handle %v:%v", clientH, h2)
		return
	}
	nvp.objDep(o1, o2)
}

func (nvp *nvproxy) objDep(o1, o2 *object) {
	if o1.deps == nil {
		o1.deps = make(map[*object]struct{})
	}
	o1.deps[o2] = struct{}{}
	if o2.rdeps == nil {
		o2.rdeps = make(map[*object]struct{})
	}
	o2.rdeps[o1] = struct{}{}
}

// objFree marks an object and its transitive dependents as freed.
//
// Compare
// src/nvidia/src/libraries/resserv/src/rs_server.c:serverFreeResourceTree().
func (nvp *nvproxy) objFree(ctx context.Context, clientH, h nvgpu.Handle) {
	// Check for recursive calls to objFree() (via objectImpl.Release()).
	// serverFreeResourceTree() permits this; we currently don't for
	// simplicity.
	if !nvp.objsFreeList.Empty() {
		panic("nvproxy.objFree called with non-empty free list (possible recursion?)")
	}

	client, ok := nvp.clients[clientH]
	if !ok {
		ctx.Warningf("nvproxy: freeing object handle %v with unknown client handle %v", h, clientH)
		return
	}
	o, ok := client.resources[h]
	if !ok {
		// When RS_COMPATABILITY_MODE is defined as true in the driver (as it
		// is in Linux), the driver permits NV_ESC_RM_FREE on nonexistent
		// handles as a no-op, and applications do this, so log at level INFO
		// rather than WARNING.
		ctx.Infof("nvproxy: freeing object with unknown handle %v:%v", clientH, h)
		return
	}
	nvp.prependFreedLockedRecursive(o)
	for !nvp.objsFreeList.Empty() {
		o2 := nvp.objsFreeList.Front()
		o2.impl.Release(ctx)
		for o3 := range o2.deps {
			delete(o3.rdeps, o2)
		}
		delete(o2.client.resources, o2.handle)
		if o2.class == nvgpu.NV01_ROOT_CLIENT {
			delete(nvp.clients, o2.handle)
		}
		nvp.objsFreeList.Remove(o2)
		delete(nvp.objsFreeSet, o2)
		if ctx.IsLogging(log.Debug) {
			ctx.Debugf("nvproxy: freed object %v:%v (class %v)", o2.client.handle, o2.handle, o2.class)
		}
	}
}

func (nvp *nvproxy) prependFreedLockedRecursive(o *object) {
	if _, ok := nvp.objsFreeSet[o]; ok {
		// o is already on the free list; move it to the front so that it
		// remains freed before our caller's o.
		nvp.objsFreeList.Remove(o)
	} else {
		nvp.objsFreeSet[o] = struct{}{}
	}
	nvp.objsFreeList.PushFront(o)

	// In the driver, freeing an object causes its children and dependents to
	// be freed first; see
	// src/nvidia/src/libraries/resserv/src/rs_server.c:serverFreeResourceTree()
	// => clientUpdatePendingFreeList_IMPL(). Replicate this freeing order.
	for o2 := range o.rdeps {
		nvp.prependFreedLockedRecursive(o2)
	}
}

// enqueueCleanup enqueues a cleanup function that will run after nvp.objsMu is
// unlocked.
func (nvp *nvproxy) enqueueCleanup(f func()) {
	nvp.objsCleanup = append(nvp.objsCleanup, f)
}

// +stateify savable
type capturedRmAllocParams struct {
	fd              *frontendFD
	ioctlParams     nvgpu.NVOS64Parameters
	rightsRequested nvgpu.RS_ACCESS_MASK
	allocParams     []byte
}

func captureRmAllocParams[Params any](fd *frontendFD, ioctlParams *nvgpu.NVOS64Parameters, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *Params) capturedRmAllocParams {
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

func newRmAllocObject[Params any](fd *frontendFD, ioctlParams *nvgpu.NVOS64Parameters, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *Params) *rmAllocObject {
	return &rmAllocObject{
		params: captureRmAllocParams(fd, ioctlParams, rightsRequested, allocParams),
	}
}

// Release implements objectImpl.Release.
func (o *rmAllocObject) Release(ctx context.Context) {
	// no-op
}

// rootClient is an objectImpl tracking a NV01_ROOT_CLIENT.
//
// +stateify savable
type rootClient struct {
	object

	// These fields are protected by nvproxy.objsMu.
	resources map[nvgpu.Handle]*object

	params capturedRmAllocParams
}

func newRootClient(fd *frontendFD, ioctlParams *nvgpu.NVOS64Parameters, rightsRequested nvgpu.RS_ACCESS_MASK, allocParams *nvgpu.Handle) *rootClient {
	return &rootClient{
		resources: make(map[nvgpu.Handle]*object),
		params:    captureRmAllocParams(fd, ioctlParams, rightsRequested, allocParams),
	}
}

// Release implements objectImpl.Release.
func (o *rootClient) Release(ctx context.Context) {
	delete(o.params.fd.clients, o.handle)
}

// osDescMem is an objectImpl tracking a NV01_MEMORY_SYSTEM_OS_DESCRIPTOR.
type osDescMem struct {
	object
	pinnedRanges []mm.PinnedRange
}

// Release implements objectImpl.Release.
func (o *osDescMem) Release(ctx context.Context) {
	// Unpin pages (which takes MM locks) without holding nvproxy locks.
	o.nvp.enqueueCleanup(func() {
		mm.Unpin(o.pinnedRanges)
		if ctx.IsLogging(log.Debug) {
			total := uint64(0)
			for _, pr := range o.pinnedRanges {
				total += uint64(pr.Source.Length())
			}
			ctx.Debugf("nvproxy: unpinned %d bytes for released OS descriptor", total)
		}
	})
}

// osEvent is an objectImpl tracking a NV01_EVENT_OS_EVENT.
type osEvent struct {
	object
}

// Release implements objectImpl.Release.
func (o *osEvent) Release(ctx context.Context) {
	// no-op
}

// virtMem is an objectImpl tracking a NV50_MEMORY_VIRTUAL.
type virtMem struct {
	object
}

// Release implements objectImpl.Release.
func (o *virtMem) Release(ctx context.Context) {
	// no-op
}
