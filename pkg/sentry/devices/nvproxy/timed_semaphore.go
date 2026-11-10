// Copyright 2026 The gVisor Authors.
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
	"time"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/log"
)

const (
	// maxTimedSemaphoreWaitNS is how far, in nanoseconds of GPU time, the
	// wait timestamp of a GF100_TIMED_SEMAPHORE_SW release may be ahead of
	// the GPU's current time.
	maxTimedSemaphoreWaitNS = 1_000_000_000

	// maxTimedSemaphorePending is the number of releases that may wait on
	// one GF100_TIMED_SEMAPHORE_SW at a time.
	maxTimedSemaphorePending = 64

	// maxTimedSemaphoresPerClient and maxTimedSemaphores are the numbers of
	// GF100_TIMED_SEMAPHORE_SW objects that one client and the sandbox may
	// hold. RM objects count against RM's resources, but these exist only in
	// the sentry. The Vulkan driver holds one per swapchain.
	maxTimedSemaphoresPerClient = 1024
	maxTimedSemaphores          = 4096

	// rmHandleBase and rmHandleLimit bound the handles RM generates for a
	// client (RS_UNIQUE_HANDLE_BASE and RS_UNIQUE_HANDLE_RANGE). A semaphore
	// may not use one, since RM could later give it to an RM object.
	rmHandleBase  = 0xcaf00000
	rmHandleLimit = 0xcaf80000

	// timedSemaphoreHandleBase is the first handle nvproxy gives a
	// GF100_TIMED_SEMAPHORE_SW allocated with no handle, just past the
	// handles RM generates.
	timedSemaphoreHandleBase = rmHandleLimit
)

// timedSemaphoreRelease is one NV9074_CTRL_CMD_RELEASE.
type timedSemaphoreRelease struct {
	notifierGPUVA  uint64
	semaphoreGPUVA uint64
	wait           uint64
	value          uint32
}

// dueTimedSemaphoreRelease is a release that goes out, with the status its
// notifier gets.
type dueTimedSemaphoreRelease struct {
	timedSemaphoreRelease
	status uint16
}

// timedSemaphoreQueue is the list of waiting releases and the flush state
// that RM keeps for each GF100_TIMED_SEMAPHORE_SW, in
// src/nvidia/src/kernel/gpu/timed_semaphore.c, with nvproxy's bounds on it.
type timedSemaphoreQueue struct {
	pending    []timedSemaphoreRelease
	flushing   bool
	flushLimit uint64
}

// releaseStatus returns the notifier status of a release that waits until
// wait, and true if it goes out at GPU time now, as
// _9074TimedSemReleaseNow() decides.
func (q *timedSemaphoreQueue) releaseStatus(wait, now uint64) (uint16, bool) {
	if wait <= now {
		return nvgpu.NV9074_NOTIFICATION_STATUS_DONE, true
	}
	if q.flushing && wait >= q.flushLimit {
		return nvgpu.NV9074_NOTIFICATION_STATUS_DONE_FLUSHED, true
	}
	return 0, false
}

// popDue removes the releases at the head of the list that go out at GPU
// time now and returns them in order, as _class9074TimerCallback() does. It
// stops at the first release that does not go out, even if releases behind
// it would.
func (q *timedSemaphoreQueue) popDue(now uint64) []dueTimedSemaphoreRelease {
	var due []dueTimedSemaphoreRelease
	n := 0
	for n < len(q.pending) {
		status, ok := q.releaseStatus(q.pending[n].wait, now)
		if !ok {
			break
		}
		due = append(due, dueTimedSemaphoreRelease{q.pending[n], status})
		n++
	}
	q.pending = append(q.pending[:0], q.pending[n:]...)
	return due
}

// release applies NV9074_CTRL_CMD_RELEASE at GPU time now. It returns false
// if the release would wait more than maxTimedSemaphoreWaitNS, or would make
// more than maxTimedSemaphorePending releases wait. Otherwise it returns the
// releases that go out now, in order, which include r if no release was
// waiting and r is due, as _9074TimedSemRequest() sends it at once.
func (q *timedSemaphoreQueue) release(r timedSemaphoreRelease, now uint64) ([]dueTimedSemaphoreRelease, bool) {
	if r.wait > now && r.wait-now > maxTimedSemaphoreWaitNS {
		return nil, false
	}
	// RM leaves due releases in the list until its timer callback runs.
	// Sending them first only moves that callback earlier.
	due := q.popDue(now)
	if len(q.pending) == 0 {
		if status, ok := q.releaseStatus(r.wait, now); ok {
			return append(due, dueTimedSemaphoreRelease{r, status}), true
		}
	}
	if len(q.pending) >= maxTimedSemaphorePending {
		return due, false
	}
	q.pending = append(q.pending, r)
	return due, true
}

// flush applies NV9074_CTRL_CMD_FLUSH at GPU time now, and returns the
// releases that go out, as tsemaCtrlCmdFlush_IMPL() does by running the
// timer callback at once while flushing.
func (q *timedSemaphoreQueue) flush(isFlushing bool, maxFlushTime, now uint64) []dueTimedSemaphoreRelease {
	q.flushing = isFlushing
	if !isFlushing {
		return nil
	}
	q.flushLimit = now + maxFlushTime
	return q.popDue(now)
}

// timedSemaphore is an objectImpl for a GF100_TIMED_SEMAPHORE_SW. It exists
// only in nvproxy, never in RM, so the class adds no RM object that a sandbox
// can reach. nvproxy answers the controls itself, and NVIDIA's userspace
// driver uses only the controls.
//
// A release writes the semaphore and its notifier as RM's
// tsemaRelease_KERNEL() does, through the application's own CPU mapping of
// the memory that the channel's device maps at the release's GPU addresses
// with NVOS46_FLAGS_KERNEL_MAPPING_ENABLE. nvproxy keeps a release waiting
// until the GPU time reaches its wait timestamp, and writes it from a timer.
//
// +stateify savable
type timedSemaphore struct {
	object

	// device is the handle of the device of the semaphore's channel. It is
	// immutable.
	device nvgpu.Handle

	// vaSpace is the handle of the VA space of the semaphore's channel. A
	// release writes through GPU mappings in virtual memory objects of that
	// VA space only. It is immutable.
	vaSpace nvgpu.Handle

	// The following fields are protected by the objsMu of the rootClient that
	// owns the semaphore. A restored sandbox runs on another GPU timer, so
	// its semaphores start with no waiting releases.

	queue    timedSemaphoreQueue `state:"nosave"`
	timer    *time.Timer         `state:"nosave"`
	released bool                `state:"nosave"`

	// subdevice is the handle of a subdevice of device that the client
	// owns, whose timer is the GPU time that releases wait for, or zero if
	// it has not been looked up.
	subdevice    nvgpu.Handle `state:"nosave"`
	subdeviceObj *object      `state:"nosave"`

	// gpuBase is the GPU time last read from the subdevice, and hostBase the
	// host monotonic time it was read at. The timer tells the GPU time from
	// them without an ioctl.
	gpuBase  uint64    `state:"nosave"`
	hostBase time.Time `state:"nosave"`
}

// Release implements objectImpl.Release. RM frees the waiting releases of a
// semaphore with it, so they never go out.
func (ts *timedSemaphore) Release(ctx context.Context) func() {
	ts.released = true
	ts.client.timedSemaphores--
	ts.nvp.clientsMu.Lock()
	ts.nvp.timedSemaphores--
	ts.nvp.clientsMu.Unlock()
	ts.dropReleasesLocked()
	return nil
}

// flushForSaveLocked sends every waiting release at once, as a flush with no
// maximum flush time does, and stops the timer, so that a checkpoint saves
// the memory with the releases written and no timer writes during the save.
//
// ts.client.objsMu must be locked.
func (ts *timedSemaphore) flushForSaveLocked() {
	if len(ts.queue.pending) == 0 {
		return
	}
	now := ts.gpuTimeFromHostLocked()
	flushing, limit := ts.queue.flushing, ts.queue.flushLimit
	due := ts.queue.flush(true, 0, now)
	ts.queue.flushing, ts.queue.flushLimit = flushing, limit
	for _, r := range due {
		ts.client.writeTimedSemaphoreReleaseLocked(ts.device, ts.vaSpace, r, now)
	}
	ts.dropReleasesLocked()
}

// dropReleasesLocked forgets the semaphore's waiting releases and stops its
// timer.
//
// ts.client.objsMu must be locked.
func (ts *timedSemaphore) dropReleasesLocked() {
	ts.queue.pending = nil
	if ts.timer != nil {
		ts.timer.Stop()
	}
}

// isChannelClass returns true if c is a class of channel that a
// GF100_TIMED_SEMAPHORE_SW may be allocated under.
func isChannelClass(c nvgpu.ClassID) bool {
	switch c {
	case nvgpu.TURING_CHANNEL_GPFIFO_A, nvgpu.AMPERE_CHANNEL_GPFIFO_A, nvgpu.HOPPER_CHANNEL_GPFIFO_A, nvgpu.BLACKWELL_CHANNEL_GPFIFO_A, nvgpu.BLACKWELL_CHANNEL_GPFIFO_B:
		return true
	}
	return false
}

// channelDeviceLocked returns the handle of the device that the channel with
// handle h belongs to, directly or through a channel group, and true, or
// false if h is not a channel of the client.
//
// c.objsMu must be locked.
func (c *rootClient) channelDeviceLocked(h nvgpu.Handle) (nvgpu.Handle, bool) {
	ch, ok := c.resources[h]
	if !ok || !isChannelClass(ch.class) {
		return nvgpu.Handle{}, false
	}
	parent, ok := c.resources[ch.parent]
	if ok && parent.class == nvgpu.KEPLER_CHANNEL_GROUP_A {
		parent, ok = c.resources[parent.parent]
	}
	if !ok || parent.class != nvgpu.NV01_DEVICE_0 {
		return nvgpu.Handle{}, false
	}
	return parent.handle, true
}

// channelVASpaceLocked returns the handle of the VA space of a channel
// allocated under parent with context share ctxShare and VA space vaSpace, as
// src/nvidia/src/kernel/gpu/fifo/kernel_channel.c:kchannelConstruct_IMPL()
// sets KernelChannel.hVASpace. A channel takes the VA space of its context
// share, or else of its channel group, which RM allocates with vaSpace for a
// channel under a device. A context share that nvproxy does not know is one
// that RM allocated for the channel group, with the group's VA space.
//
// c.objsMu must be locked.
func (c *rootClient) channelVASpaceLocked(parent, ctxShare, vaSpace nvgpu.Handle) nvgpu.Handle {
	if o, ok := c.resources[ctxShare]; ok && ctxShare.Val != nvgpu.NV01_NULL_OBJECT {
		return o.vaSpace
	}
	if o, ok := c.resources[parent]; ok && o.class == nvgpu.KEPLER_CHANNEL_GROUP_A {
		return o.vaSpace
	}
	return vaSpace
}

// newTimedSemaphoreHandleLocked returns a handle that no object of the client
// uses, for a GF100_TIMED_SEMAPHORE_SW allocated with no handle.
//
// c.objsMu must be locked.
func (c *rootClient) newTimedSemaphoreHandleLocked() (nvgpu.Handle, bool) {
	if c.nextTimedSemaphoreHandle < timedSemaphoreHandleBase {
		c.nextTimedSemaphoreHandle = timedSemaphoreHandleBase
	}
	start := c.nextTimedSemaphoreHandle
	for _, r := range [][2]uint64{{uint64(start), 1 << 32}, {timedSemaphoreHandleBase, uint64(start)}} {
		for v := r[0]; v < r[1]; v++ {
			h := nvgpu.Handle{Val: uint32(v)}
			if _, ok := c.resources[h]; !ok {
				c.nextTimedSemaphoreHandle = uint32(v + 1)
				return h, true
			}
		}
	}
	return nvgpu.Handle{}, false
}

// rmAllocTimedSemaphore handles NV_ESC_RM_ALLOC of GF100_TIMED_SEMAPHORE_SW,
// which takes no parameters and must be the child of a channel, without
// asking RM.
func rmAllocTimedSemaphore(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS64_PARAMETERS, isNVOS64 bool) (uintptr, error) {
	status := uint32(nvgpu.NV_OK)
	client, unlock := fi.fd.dev.nvp.getClientWithLock(fi.ctx, ioctlParams.HRoot)
	if client == nil {
		status = nvgpu.NV_ERR_INVALID_CLIENT
	} else {
		status = allocTimedSemaphoreLocked(fi.ctx, fi.fd.dev.nvp, client, ioctlParams)
		unlock()
	}
	ioctlParams.Status = status
	outIoctlParams := nvgpu.GetRmAllocParamObj(isNVOS64)
	outIoctlParams.FromOS64(*ioctlParams)
	if _, err := outIoctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return 0, err
	}
	return 0, nil
}

// allocTimedSemaphoreLocked records a GF100_TIMED_SEMAPHORE_SW allocated by
// ioctlParams in client, setting ioctlParams.HObjectNew if the application
// left it zero for RM to pick, and returns the status RM would return.
//
// client.objsMu must be locked.
func allocTimedSemaphoreLocked(ctx context.Context, nvp *nvproxy, client *rootClient, ioctlParams *nvgpu.NVOS64_PARAMETERS) uint32 {
	device, ok := client.channelDeviceLocked(ioctlParams.HObjectParent)
	if !ok {
		return nvgpu.NV_ERR_INVALID_OBJECT_PARENT
	}
	if client.timedSemaphores >= maxTimedSemaphoresPerClient {
		return nvgpu.NV_ERR_INSUFFICIENT_RESOURCES
	}
	h := ioctlParams.HObjectNew
	if h.Val == nvgpu.NV01_NULL_OBJECT {
		if h, ok = client.newTimedSemaphoreHandleLocked(); !ok {
			return nvgpu.NV_ERR_INSERT_DUPLICATE_NAME
		}
	} else if h.Val >= rmHandleBase && h.Val < rmHandleLimit {
		return nvgpu.NV_ERR_INVALID_OBJECT_HANDLE
	} else if _, ok := client.resources[h]; ok {
		return nvgpu.NV_ERR_INSERT_DUPLICATE_NAME
	}
	nvp.clientsMu.Lock()
	full := nvp.timedSemaphores >= maxTimedSemaphores
	if !full {
		nvp.timedSemaphores++
	}
	nvp.clientsMu.Unlock()
	if full {
		return nvgpu.NV_ERR_INSUFFICIENT_RESOURCES
	}
	ts := &timedSemaphore{device: device, vaSpace: client.resources[ioctlParams.HObjectParent].vaSpace}
	nvp.objAdd(ctx, client, h, ioctlParams.HClass, ts, ioctlParams.HObjectParent)
	client.timedSemaphores++
	ioctlParams.HObjectNew = h
	return nvgpu.NV_OK
}

// usedOnlyByNvproxyLocked returns true if h is the handle of an object that
// exists only in nvproxy, which RM does not know.
//
// c.objsMu must be locked.
func (c *rootClient) usedOnlyByNvproxyLocked(h nvgpu.Handle) bool {
	o, ok := c.resources[h]
	if !ok {
		return false
	}
	_, ok = o.impl.(*timedSemaphore)
	return ok
}

// timedSemaphoreLocked returns the GF100_TIMED_SEMAPHORE_SW with handle h, or
// the status RM returns for a control of the class on h.
//
// c.objsMu must be locked.
func (c *rootClient) timedSemaphoreLocked(h nvgpu.Handle) (*timedSemaphore, uint32) {
	o, ok := c.resources[h]
	if !ok {
		return nil, nvgpu.NV_ERR_INVALID_OBJECT_HANDLE
	}
	ts, ok := o.impl.(*timedSemaphore)
	if !ok {
		return nil, nvgpu.NV_ERR_NOT_SUPPORTED
	}
	return ts, nvgpu.NV_OK
}

// subdeviceLocked returns the handle of a subdevice of the semaphore's device
// that its client owns, or false if there is none.
//
// ts.client.objsMu must be locked.
func (ts *timedSemaphore) subdeviceLocked() (nvgpu.Handle, bool) {
	if ts.subdeviceObj != nil && ts.client.resources[ts.subdevice] == ts.subdeviceObj {
		return ts.subdevice, true
	}
	ts.subdeviceObj = nil
	for h, o := range ts.client.resources {
		if o.class == nvgpu.NV20_SUBDEVICE_0 && o.parent == ts.device {
			ts.subdevice, ts.subdeviceObj = h, o
			return h, true
		}
	}
	return nvgpu.Handle{}, false
}

// gpuTimeLocked reads the GPU time of the semaphore's device, with
// NV2080_CTRL_CMD_TIMER_GET_TIME on a subdevice, which reads the same timer
// as RM's NV9074_CTRL_CMD_GET_TIME. It returns RM's status, and
// NV_ERR_INVALID_STATE if the client owns no subdevice of the device.
//
// ts.client.objsMu must be locked.
func (ts *timedSemaphore) gpuTimeLocked(fi *frontendIoctlState) (uint64, uint32, error) {
	sub, ok := ts.subdeviceLocked()
	if !ok {
		return 0, nvgpu.NV_ERR_INVALID_STATE, nil
	}
	now, status, err := timerGetTime(fi, ts.client.handle, sub)
	if err == nil && status == nvgpu.NV_OK {
		ts.gpuBase = now
		ts.hostBase = time.Now()
	}
	return now, status, err
}

// gpuTimeFromHostLocked returns the GPU time, told from the last read and the
// host monotonic time since. Over the at most maxTimedSemaphoreWaitNS that a
// release waits, the two clocks drift apart by far less than a timer's
// latency.
//
// ts.client.objsMu must be locked.
func (ts *timedSemaphore) gpuTimeFromHostLocked() uint64 {
	return ts.gpuBase + uint64(time.Since(ts.hostBase))
}

// sendLocked writes due releases at GPU time now, in order, and arms the
// timer for the release at the head of the list, if any.
//
// ts.client.objsMu must be locked.
func (ts *timedSemaphore) sendLocked(due []dueTimedSemaphoreRelease, now uint64) {
	for _, r := range due {
		ts.client.writeTimedSemaphoreReleaseLocked(ts.device, ts.vaSpace, r, now)
	}
	if len(ts.queue.pending) == 0 {
		return
	}
	d := time.Duration(0)
	if wait := ts.queue.pending[0].wait; wait > now {
		d = time.Duration(wait - now)
	}
	if ts.timer == nil {
		ts.timer = time.AfterFunc(d, ts.timerFired)
	} else {
		ts.timer.Reset(d)
	}
}

// timerFired writes the releases that have come due.
func (ts *timedSemaphore) timerFired() {
	ts.client.objsMu.Lock()
	defer ts.client.objsMu.Unlock()
	if ts.released || ts.client.released {
		return
	}
	now := ts.gpuTimeFromHostLocked()
	ts.sendLocked(ts.queue.popDue(now), now)
}

// writeTimedSemaphoreReleaseLocked writes release r at GPU time now as RM's
// tsemaRelease_KERNEL() does, the semaphore's timestamp and then its value,
// then the notifier's timestamp and then its status. RM writes each through
// the kernel mapping of the memory that device maps at the GPU address in VA
// space vaSpace, and skips a structure that no mapping with
// NVOS46_FLAGS_KERNEL_MAPPING_ENABLE covers.
//
// c.objsMu must be locked.
func (c *rootClient) writeTimedSemaphoreReleaseLocked(device, vaSpace nvgpu.Handle, r dueTimedSemaphoreRelease, now uint64) {
	// NvGpuSemaphore, from src/common/sdk/nvidia/inc/nvgputypes.h, and
	// semaphoreFillGPUVATimestamp().
	if mf, off, ok := c.kernelMappedLocked(device, vaSpace, r.semaphoreGPUVA, 16); ok {
		mf.storeUint32s(off, []uint32Store{
			{8, uint32(now)},
			{12, uint32(now >> 32)},
			{0, r.value},
		})
	}
	// NOTIFICATION, from
	// src/nvidia/inc/kernel/gpu/mem_mgr/virt_mem_allocator_common.h, and
	// notifyFillNOTIFICATION().
	if mf, off, ok := c.kernelMappedLocked(device, vaSpace, r.notifierGPUVA, 16); ok {
		mf.storeUint32s(off, []uint32Store{
			{8, 0},
			{4, uint32(now >> 32)},
			{0, uint32(now)},
			{12, uint32(r.status) << 16},
		})
	}
}

// uint32Store is one 32-bit store at an offset.
type uint32Store struct {
	off   uint64
	value uint32
}

// kernelDMAMapping records a NV_ESC_RM_MAP_MEMORY_DMA with
// NVOS46_FLAGS_KERNEL_MAPPING_ENABLE.
type kernelDMAMapping struct {
	device  nvgpu.Handle
	virt    nvgpu.Handle
	virtObj *object
	mem     nvgpu.Handle
	memObj  *object
	offset  uint64
	length  uint64
	gpuVA   uint64
}

// cpuMapping records a NV_ESC_RM_MAP_MEMORY, or a NV_ESC_RM_ALLOC_MEMORY of
// NV01_MEMORY_SYSTEM with an mmap context, whose file holds the application's
// CPU mapping of the memory. Offset 0 of the file's mapping is the memory at
// offset, which is page-aligned since RM maps from the page that holds the
// offset the application asked for (nv_align_mmap_offset_length()), and is 0
// for an allocation.
type cpuMapping struct {
	mf     *frontendFDMemmapFile
	mem    nvgpu.Handle
	memObj *object
	offset uint64
	length uint64
}

// rangeContains returns true if [base, base+length) contains [addr,
// addr+size).
func rangeContains(base, length, addr, size uint64) bool {
	return addr >= base && addr-base <= length && length-(addr-base) >= size
}

// kernelMappedLocked returns the file that holds the application's CPU
// mapping of the memory that device maps at GPU addresses [gpuVA, gpuVA+size)
// with a kernel mapping in a virtual memory object of VA space vaSpace, and
// the offset of gpuVA in that file's mapping. RM looks the GPU address up the
// same way, in src/nvidia/src/kernel/rmapi/mapping_list.c:CliGetDmaMappingInfo()
// with virtmemMatchesVASpace().
//
// c.objsMu must be locked.
func (c *rootClient) kernelMappedLocked(device, vaSpace nvgpu.Handle, gpuVA, size uint64) (*frontendFDMemmapFile, uint64, bool) {
	for i := len(c.kernelDMAMappings) - 1; i >= 0; i-- {
		m := &c.kernelDMAMappings[i]
		if m.device != device || m.virtObj.vaSpace != vaSpace || !rangeContains(m.gpuVA, m.length, gpuVA, size) || !c.kernelDMAMappingValidLocked(m) {
			continue
		}
		memOff := m.offset + (gpuVA - m.gpuVA)
		for j := len(c.cpuMappings) - 1; j >= 0; j-- {
			cm := &c.cpuMappings[j]
			if cm.memObj == m.memObj && rangeContains(cm.offset, cm.length, memOff, size) && c.cpuMappingValidLocked(cm) {
				return cm.mf, memOff - cm.offset, true
			}
		}
		return nil, 0, false
	}
	return nil, 0, false
}

// c.objsMu must be locked.
func (c *rootClient) kernelDMAMappingValidLocked(m *kernelDMAMapping) bool {
	return c.resources[m.virt] == m.virtObj && c.resources[m.mem] == m.memObj
}

// c.objsMu must be locked.
func (c *rootClient) cpuMappingValidLocked(m *cpuMapping) bool {
	return c.resources[m.mem] == m.memObj && !m.mf.isClosed()
}

// recordKernelDMAMappingLocked records a successful NV_ESC_RM_MAP_MEMORY_DMA
// with NVOS46_FLAGS_KERNEL_MAPPING_ENABLE. RM finds a release's mapping among
// the virtual memory of the semaphore's device, so the mapping is recorded
// under the device of the virtual memory object, not under the handle the
// application passed, which may be a subdevice.
//
// c.objsMu must be locked.
func (c *rootClient) recordKernelDMAMappingLocked(virt, mem nvgpu.Handle, offset, length, gpuVA uint64) {
	virtObj, memObj := c.resources[virt], c.resources[mem]
	if virtObj == nil || memObj == nil {
		return
	}
	// RM looks a release's address up among virtual memory objects only.
	if virtObj.class != nvgpu.NV50_MEMORY_VIRTUAL && virtObj.class != nvgpu.NV01_MEMORY_VIRTUAL {
		return
	}
	device, ok := c.resources[virtObj.parent]
	if ok && device.class == nvgpu.NV20_SUBDEVICE_0 {
		device, ok = c.resources[device.parent]
	}
	if !ok || device.class != nvgpu.NV01_DEVICE_0 {
		return
	}
	if len(c.kernelDMAMappings) >= c.kernelDMAMappingsPruneAt {
		valid := c.kernelDMAMappings[:0]
		for i := range c.kernelDMAMappings {
			if c.kernelDMAMappingValidLocked(&c.kernelDMAMappings[i]) {
				valid = append(valid, c.kernelDMAMappings[i])
			}
		}
		c.kernelDMAMappings = valid
		c.kernelDMAMappingsPruneAt = max(64, 2*len(valid))
	}
	c.kernelDMAMappings = append(c.kernelDMAMappings, kernelDMAMapping{
		device:  device.handle,
		virt:    virt,
		virtObj: virtObj,
		mem:     mem,
		memObj:  memObj,
		offset:  offset,
		length:  length,
		gpuVA:   gpuVA,
	})
}

// forgetKernelDMAMappingLocked removes the recorded mappings of virt that
// contain GPU address gpuVA, after a successful NV_ESC_RM_UNMAP_MEMORY_DMA.
//
// c.objsMu must be locked.
func (c *rootClient) forgetKernelDMAMappingLocked(virt nvgpu.Handle, gpuVA uint64) {
	kept := c.kernelDMAMappings[:0]
	for _, m := range c.kernelDMAMappings {
		if m.virt == virt && rangeContains(m.gpuVA, m.length, gpuVA, 1) {
			continue
		}
		kept = append(kept, m)
	}
	c.kernelDMAMappings = kept
}

// recordCPUMappingLocked records a successful NV_ESC_RM_MAP_MEMORY, or
// NV_ESC_RM_ALLOC_MEMORY with an mmap context, whose file is mf, of length
// bytes of the memory from offset. mf maps length bytes from the start of the
// page that holds offset.
//
// c.objsMu must be locked.
func (c *rootClient) recordCPUMappingLocked(mf *frontendFDMemmapFile, mem nvgpu.Handle, offset, length uint64) {
	memObj := c.resources[mem]
	if memObj == nil || length == 0 {
		return
	}
	offset = hostarch.PageRoundDown(offset)
	if len(c.cpuMappings) >= c.cpuMappingsPruneAt {
		valid := c.cpuMappings[:0]
		for i := range c.cpuMappings {
			if c.cpuMappingValidLocked(&c.cpuMappings[i]) {
				valid = append(valid, c.cpuMappings[i])
			}
		}
		c.cpuMappings = valid
		c.cpuMappingsPruneAt = max(64, 2*len(valid))
	}
	c.cpuMappings = append(c.cpuMappings, cpuMapping{
		mf:     mf,
		mem:    mem,
		memObj: memObj,
		offset: offset,
		length: length,
	})
}

// timedSemaphoreControl runs control f on the GF100_TIMED_SEMAPHORE_SW named
// by ioctlParams with its client's objsMu locked, and copies the status and
// ctrlParams out to the application after unlocking.
func timedSemaphoreControl[Params any, PtrParams marshalPtr[Params]](fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS, f func(ts *timedSemaphore, ctrlParams PtrParams) (uint32, error)) (uintptr, error) {
	var ctrlParamsValue Params
	ctrlParams := PtrParams(&ctrlParamsValue)
	if ctrlParams.SizeBytes() != int(ioctlParams.ParamsSize) {
		return 0, linuxerr.EINVAL
	}
	if _, err := ctrlParams.CopyIn(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}
	client, unlock := fi.fd.dev.nvp.getClientWithLock(fi.ctx, ioctlParams.HClient)
	if client == nil {
		return 0, frontendFailWithStatus(fi, ioctlParams, nvgpu.NV_ERR_INVALID_CLIENT)
	}
	ts, status := client.timedSemaphoreLocked(ioctlParams.HObject)
	var err error
	if ts != nil {
		status, err = f(ts, ctrlParams)
	}
	unlock()
	if err != nil {
		return 0, err
	}
	if status != nvgpu.NV_OK {
		return 0, frontendFailWithStatus(fi, ioctlParams, status)
	}
	if _, err := ctrlParams.CopyOut(fi.t, addrFromP64(ioctlParams.Params)); err != nil {
		return 0, err
	}
	ioctlParams.Status = nvgpu.NV_OK
	if _, err := ioctlParams.CopyOut(fi.t, fi.ioctlParamsAddr); err != nil {
		return 0, err
	}
	return 0, nil
}

// ctrlTimedSemaphoreGetTime handles NV9074_CTRL_CMD_GET_TIME.
func ctrlTimedSemaphoreGetTime(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) (uintptr, error) {
	return timedSemaphoreControl(fi, ioctlParams, func(ts *timedSemaphore, p *nvgpu.NV9074_CTRL_CMD_GET_TIME_PARAMS) (uint32, error) {
		now, status, err := ts.gpuTimeLocked(fi)
		p.CurrentTime = now
		return status, err
	})
}

// ctrlTimedSemaphoreFlush handles NV9074_CTRL_CMD_FLUSH.
func ctrlTimedSemaphoreFlush(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) (uintptr, error) {
	return timedSemaphoreControl(fi, ioctlParams, func(ts *timedSemaphore, p *nvgpu.NV9074_CTRL_CMD_FLUSH_PARAMS) (uint32, error) {
		now, status, err := ts.gpuTimeLocked(fi)
		if err != nil || status != nvgpu.NV_OK {
			return status, err
		}
		ts.sendLocked(ts.queue.flush(p.IsFlushing != 0, p.MaxFlushTime, now), now)
		return nvgpu.NV_OK, nil
	})
}

// ctrlTimedSemaphoreRelease handles NV9074_CTRL_CMD_RELEASE. It fails a
// release that timedSemaphoreQueue.release refuses with
// NV_ERR_INVALID_ARGUMENT, as RM does for invalid parameters. The notify
// flag needs no handling, since no event can be allocated under a semaphore
// that RM does not have.
func ctrlTimedSemaphoreRelease(fi *frontendIoctlState, ioctlParams *nvgpu.NVOS54_PARAMETERS) (uintptr, error) {
	return timedSemaphoreControl(fi, ioctlParams, func(ts *timedSemaphore, p *nvgpu.NV9074_CTRL_CMD_RELEASE_PARAMS) (uint32, error) {
		now, status, err := ts.gpuTimeLocked(fi)
		if err != nil || status != nvgpu.NV_OK {
			return status, err
		}
		due, ok := ts.queue.release(timedSemaphoreRelease{
			notifierGPUVA:  p.NotifierGPUVA,
			semaphoreGPUVA: p.SemaphoreGPUVA,
			wait:           p.WaitTimestamp,
			value:          p.ReleaseValue,
		}, now)
		ts.sendLocked(due, now)
		if !ok {
			if log.IsLogging(log.Debug) {
				fi.ctx.Debugf("nvproxy: refused timed semaphore release waiting until %d at GPU time %d with %d waiting", p.WaitTimestamp, now, len(ts.queue.pending))
			}
			return nvgpu.NV_ERR_INVALID_ARGUMENT, nil
		}
		return nvgpu.NV_OK, nil
	})
}
