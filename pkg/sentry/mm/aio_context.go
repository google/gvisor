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

package mm

import (
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/refs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/memmap"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usage"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// aioManager creates and manages asynchronous I/O contexts.
//
// +stateify savable
type aioManager struct {
	// mu protects below.
	mu sync.Mutex `state:"nosave"`

	// aioContexts is the set of asynchronous I/O contexts.
	contexts map[uint64]*AIOContext
}

func (a *aioManager) destroy() {
	a.mu.Lock()
	defer a.mu.Unlock()

	for _, ctx := range a.contexts {
		ctx.destroy()
	}
}

// newAIOContext creates a new context for asynchronous I/O.
//
// Returns false if 'id' is currently in use.
func (a *aioManager) newAIOContext(events uint32, id uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if _, ok := a.contexts[id]; ok {
		return false
	}

	a.contexts[id] = &AIOContext{
		done:           make(chan struct{}, 1),
		maxOutstanding: events,
	}
	return true
}

// destroyAIOContext destroys an asynchronous I/O context.
//
// False is returned if the context does not exist.
func (a *aioManager) destroyAIOContext(id uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	ctx, ok := a.contexts[id]
	if !ok {
		return false
	}
	delete(a.contexts, id)
	ctx.destroy()
	return true
}

// lookupAIOContext looks up the given context.
//
// Returns false if context does not exist.
func (a *aioManager) lookupAIOContext(id uint64) (*AIOContext, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	ctx, ok := a.contexts[id]
	return ctx, ok
}

// ioResult is a completed I/O operation.
//
// +stateify savable
type ioResult struct {
	data interface{}
	ioEntry
}

// AIOContext is a single asynchronous I/O context.
//
// +stateify savable
type AIOContext struct {
	// done is the notification channel used for all requests.
	done chan struct{} `state:"nosave"`

	// mu protects below.
	mu sync.Mutex `state:"nosave"`

	// results is the set of completed requests.
	results ioList

	// maxOutstanding is the maximum number of outstanding entries; this value
	// is immutable.
	maxOutstanding uint32

	// outstanding is the number of requests outstanding; this will effectively
	// be the number of entries in the result list or that are expected to be
	// added to the result list.
	outstanding uint32

	// dead is set when the context is destroyed.
	dead bool `state:"zerovalue"`
}

// destroy marks the context dead.
func (ctx *AIOContext) destroy() {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.dead = true
	if ctx.outstanding == 0 {
		close(ctx.done)
	}
}

// Prepare reserves space for a new request, returning true if available.
// Returns false if the context is busy.
func (ctx *AIOContext) Prepare() bool {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.outstanding >= ctx.maxOutstanding {
		return false
	}
	ctx.outstanding++
	return true
}

// PopRequest pops a completed request if available, this function does not do
// any blocking. Returns false if no request is available.
func (ctx *AIOContext) PopRequest() (interface{}, bool) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	// Is there anything ready?
	if e := ctx.results.Front(); e != nil {
		ctx.results.Remove(e)
		ctx.outstanding--
		if ctx.outstanding == 0 && ctx.dead {
			close(ctx.done)
		}
		return e.data, true
	}
	return nil, false
}

// FinishRequest finishes a pending request. It queues up the data
// and notifies listeners.
func (ctx *AIOContext) FinishRequest(data interface{}) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	// Push to the list and notify opportunistically. The channel notify
	// here is guaranteed to be safe because outstanding must be non-zero.
	// The done channel is only closed when outstanding reaches zero.
	ctx.results.PushBack(&ioResult{data: data})

	select {
	case ctx.done <- struct{}{}:
	default:
	}
}

// WaitChannel returns a channel that is notified when an AIO request is
// completed.
//
// The boolean return value indicates whether or not the context is active.
func (ctx *AIOContext) WaitChannel() (chan struct{}, bool) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.outstanding == 0 && ctx.dead {
		return nil, false
	}
	return ctx.done, true
}

// aioMappable implements memmap.MappingIdentity and memmap.Mappable for AIO
// ring buffers.
//
// +stateify savable
type aioMappable struct {
	refs.AtomicRefCount

	p  platform.Platform
	fr platform.FileRange
}

var aioRingBufferSize = uint64(usermem.Addr(linux.AIORingSize).MustRoundUp())

func newAIOMappable(p platform.Platform) (*aioMappable, error) {
	fr, err := p.Memory().Allocate(aioRingBufferSize, usage.Anonymous)
	if err != nil {
		return nil, err
	}
	return &aioMappable{p: p, fr: fr}, nil
}

// DecRef implements refs.RefCounter.DecRef.
func (m *aioMappable) DecRef() {
	m.AtomicRefCount.DecRefWithDestructor(func() {
		m.p.Memory().DecRef(m.fr)
	})
}

// MappedName implements memmap.MappingIdentity.MappedName.
func (m *aioMappable) MappedName(ctx context.Context) string {
	return "[aio]"
}

// DeviceID implements memmap.MappingIdentity.DeviceID.
func (m *aioMappable) DeviceID() uint64 {
	return 0
}

// InodeID implements memmap.MappingIdentity.InodeID.
func (m *aioMappable) InodeID() uint64 {
	return 0
}

// Msync implements memmap.MappingIdentity.Msync.
func (m *aioMappable) Msync(ctx context.Context, mr memmap.MappableRange) error {
	// Linux: aio_ring_fops.fsync == NULL
	return syserror.EINVAL
}

// AddMapping implements memmap.Mappable.AddMapping.
func (m *aioMappable) AddMapping(_ context.Context, _ memmap.MappingSpace, ar usermem.AddrRange, offset uint64, _ bool) error {
	// Don't allow mappings to be expanded (in Linux, fs/aio.c:aio_ring_mmap()
	// sets VM_DONTEXPAND).
	if offset != 0 || uint64(ar.Length()) != aioRingBufferSize {
		return syserror.EFAULT
	}
	return nil
}

// RemoveMapping implements memmap.Mappable.RemoveMapping.
func (m *aioMappable) RemoveMapping(context.Context, memmap.MappingSpace, usermem.AddrRange, uint64, bool) {
}

// CopyMapping implements memmap.Mappable.CopyMapping.
func (m *aioMappable) CopyMapping(ctx context.Context, ms memmap.MappingSpace, srcAR, dstAR usermem.AddrRange, offset uint64, _ bool) error {
	// Don't allow mappings to be expanded (in Linux, fs/aio.c:aio_ring_mmap()
	// sets VM_DONTEXPAND).
	if offset != 0 || uint64(dstAR.Length()) != aioRingBufferSize {
		return syserror.EFAULT
	}
	// Require that the mapping correspond to a live AIOContext. Compare
	// Linux's fs/aio.c:aio_ring_mremap().
	mm, ok := ms.(*MemoryManager)
	if !ok {
		return syserror.EINVAL
	}
	am := &mm.aioManager
	am.mu.Lock()
	defer am.mu.Unlock()
	oldID := uint64(srcAR.Start)
	aioCtx, ok := am.contexts[oldID]
	if !ok {
		return syserror.EINVAL
	}
	aioCtx.mu.Lock()
	defer aioCtx.mu.Unlock()
	if aioCtx.dead {
		return syserror.EINVAL
	}
	// Use the new ID for the AIOContext.
	am.contexts[uint64(dstAR.Start)] = aioCtx
	delete(am.contexts, oldID)
	return nil
}

// Translate implements memmap.Mappable.Translate.
func (m *aioMappable) Translate(ctx context.Context, required, optional memmap.MappableRange, at usermem.AccessType) ([]memmap.Translation, error) {
	var err error
	if required.End > m.fr.Length() {
		err = &memmap.BusError{syserror.EFAULT}
	}
	if source := optional.Intersect(memmap.MappableRange{0, m.fr.Length()}); source.Length() != 0 {
		return []memmap.Translation{
			{
				Source: source,
				File:   m.p.Memory(),
				Offset: m.fr.Start + source.Start,
			},
		}, err
	}
	return nil, err
}

// InvalidateUnsavable implements memmap.Mappable.InvalidateUnsavable.
func (m *aioMappable) InvalidateUnsavable(ctx context.Context) error {
	return nil
}

// NewAIOContext creates a new context for asynchronous I/O.
//
// NewAIOContext is analogous to Linux's fs/aio.c:ioctx_alloc().
func (mm *MemoryManager) NewAIOContext(ctx context.Context, events uint32) (uint64, error) {
	// libaio get_ioevents() expects context "handle" to be a valid address.
	// libaio peeks inside looking for a magic number. This function allocates
	// a page per context and keeps it set to zeroes to ensure it will not
	// match AIO_RING_MAGIC and make libaio happy.
	m, err := newAIOMappable(mm.p)
	if err != nil {
		return 0, err
	}
	defer m.DecRef()
	addr, err := mm.MMap(ctx, memmap.MMapOpts{
		Length:          aioRingBufferSize,
		MappingIdentity: m,
		Mappable:        m,
		// TODO: Linux does "do_mmap_pgoff(..., PROT_READ |
		// PROT_WRITE, ...)" in fs/aio.c:aio_setup_ring(); why do we make this
		// mapping read-only?
		Perms:    usermem.Read,
		MaxPerms: usermem.Read,
	})
	if err != nil {
		return 0, err
	}
	id := uint64(addr)
	if !mm.aioManager.newAIOContext(events, id) {
		mm.MUnmap(ctx, addr, aioRingBufferSize)
		return 0, syserror.EINVAL
	}
	return id, nil
}

// DestroyAIOContext destroys an asynchronous I/O context. It returns false if
// the context does not exist.
func (mm *MemoryManager) DestroyAIOContext(ctx context.Context, id uint64) bool {
	if _, ok := mm.LookupAIOContext(ctx, id); !ok {
		return false
	}

	// Only unmaps after it assured that the address is a valid aio context to
	// prevent random memory from been unmapped.
	//
	// Note: It's possible to unmap this address and map something else into
	// the same address. Then it would be unmapping memory that it doesn't own.
	// This is, however, the way Linux implements AIO. Keeps the same [weird]
	// semantics in case anyone relies on it.
	mm.MUnmap(ctx, usermem.Addr(id), aioRingBufferSize)

	return mm.aioManager.destroyAIOContext(id)
}

// LookupAIOContext looks up the given context. It returns false if the context
// does not exist.
func (mm *MemoryManager) LookupAIOContext(ctx context.Context, id uint64) (*AIOContext, bool) {
	aioCtx, ok := mm.aioManager.lookupAIOContext(id)
	if !ok {
		return nil, false
	}

	// Protect against 'ids' that are inaccessible (Linux also reads 4 bytes
	// from id).
	var buf [4]byte
	_, err := mm.CopyIn(ctx, usermem.Addr(id), buf[:], usermem.IOOpts{})
	if err != nil {
		return nil, false
	}

	return aioCtx, true
}
