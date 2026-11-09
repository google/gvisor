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
	"testing"

	"gvisor.dev/gvisor/pkg/abi/nvgpu"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
)

// TestTimedSemaphoreNeedsDisplay checks that every driver ABI handles
// GF100_TIMED_SEMAPHORE_SW and its controls with the display capability only.
func TestTimedSemaphoreNeedsDisplay(t *testing.T) {
	Init()
	for version, entry := range abis {
		abi := entry.cons()
		if h, ok := abi.allocationClass[nvgpu.GF100_TIMED_SEMAPHORE_SW]; !ok {
			t.Errorf("driver %v does not handle GF100_TIMED_SEMAPHORE_SW", version)
		} else if h.capSet != nvconf.CapDisplay {
			t.Errorf("driver %v gates GF100_TIMED_SEMAPHORE_SW on %v, want display", version, h.capSet)
		}
		for _, cmd := range []uint32{nvgpu.NV9074_CTRL_CMD_FLUSH, nvgpu.NV9074_CTRL_CMD_GET_TIME, nvgpu.NV9074_CTRL_CMD_RELEASE} {
			if h, ok := abi.controlCmd[cmd]; !ok {
				t.Errorf("driver %v does not handle control %#x", version, cmd)
			} else if h.capSet != nvconf.CapDisplay {
				t.Errorf("driver %v gates control %#x on %v, want display", version, cmd, h.capSet)
			}
		}
	}
}

func release(wait uint64, value uint32) timedSemaphoreRelease {
	return timedSemaphoreRelease{notifierGPUVA: 0x1000, semaphoreGPUVA: 0x1010, wait: wait, value: value}
}

func values(due []dueTimedSemaphoreRelease) []uint32 {
	var vs []uint32
	for _, r := range due {
		vs = append(vs, r.value)
	}
	return vs
}

func equalValues(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestTimedSemaphoreAdmitsReleaseWithinMaxWait(t *testing.T) {
	var q timedSemaphoreQueue
	if _, ok := q.release(release(1000+maxTimedSemaphoreWaitNS, 1), 1000); !ok {
		t.Errorf("release waiting %d ns was refused", maxTimedSemaphoreWaitNS)
	}
}

func TestTimedSemaphoreRefusesReleaseBeyondMaxWait(t *testing.T) {
	var q timedSemaphoreQueue
	if _, ok := q.release(release(1000+maxTimedSemaphoreWaitNS+1, 1), 1000); ok {
		t.Errorf("release waiting %d ns was admitted", maxTimedSemaphoreWaitNS+1)
	}
}

func TestTimedSemaphoreRefusesReleaseAtLastTimestamp(t *testing.T) {
	var q timedSemaphoreQueue
	if _, ok := q.release(release(^uint64(0), 1), 1000); ok {
		t.Errorf("release waiting until the last timestamp was admitted")
	}
}

func TestTimedSemaphoreLimitsPendingReleases(t *testing.T) {
	var q timedSemaphoreQueue
	for i := 0; i < maxTimedSemaphorePending; i++ {
		if _, ok := q.release(release(2000, uint32(i)), 1000); !ok {
			t.Fatalf("release %d was refused", i+1)
		}
	}
	if _, ok := q.release(release(2000, 99), 1000); ok {
		t.Errorf("release %d was admitted", maxTimedSemaphorePending+1)
	}
}

func TestTimedSemaphoreDueReleaseGoesOutAtOnce(t *testing.T) {
	var q timedSemaphoreQueue
	due, ok := q.release(release(1000, 7), 1000)
	if !ok || !equalValues(values(due), []uint32{7}) || len(q.pending) != 0 {
		t.Errorf("due release: got out %v, admitted %v, %d waiting, want out [7], admitted, 0 waiting", values(due), ok, len(q.pending))
	}
	if due[0].status != nvgpu.NV9074_NOTIFICATION_STATUS_DONE {
		t.Errorf("due release has status %#x, want DONE", due[0].status)
	}
}

func TestTimedSemaphoreReleasesGoOutInOrderWhenDue(t *testing.T) {
	var q timedSemaphoreQueue
	q.release(release(2000, 1), 1000)
	q.release(release(3000, 2), 1000)
	q.release(release(4000, 3), 1000)
	if got := values(q.popDue(3000)); !equalValues(got, []uint32{1, 2}) {
		t.Errorf("out at 3000: got %v, want [1 2]", got)
	}
	if got := values(q.popDue(4000)); !equalValues(got, []uint32{3}) {
		t.Errorf("out at 4000: got %v, want [3]", got)
	}
}

func TestTimedSemaphoreDueReleasesFreeTheirSlots(t *testing.T) {
	var q timedSemaphoreQueue
	for i := 0; i < maxTimedSemaphorePending; i++ {
		q.release(release(2000, uint32(i)), 1000)
	}
	due, ok := q.release(release(3000, 99), 2000)
	if !ok || len(due) != maxTimedSemaphorePending {
		t.Errorf("release after every waiting release came due: admitted %v with %d out, want admitted with %d out", ok, len(due), maxTimedSemaphorePending)
	}
}

// RM queues a release whose wait timestamp has passed behind the releases
// already waiting.
func TestTimedSemaphoreDueReleaseWaitsBehindWaitingRelease(t *testing.T) {
	var q timedSemaphoreQueue
	q.release(release(2000, 1), 1000)
	due, _ := q.release(release(1000, 2), 1000)
	if len(due) != 0 || len(q.pending) != 2 {
		t.Errorf("due release behind a waiting one: %v out, %d waiting, want none out, 2 waiting", values(due), len(q.pending))
	}
}

// RM sends releases from the head of its list only, so a due release behind
// one that is not due stays.
func TestTimedSemaphoreDueReleaseBehindLaterReleaseWaits(t *testing.T) {
	var q timedSemaphoreQueue
	q.release(release(3000, 1), 1000)
	q.release(release(2000, 2), 1000)
	if got := values(q.popDue(2500)); len(got) != 0 {
		t.Errorf("out at 2500: got %v, want none", got)
	}
	if got := values(q.popDue(3000)); !equalValues(got, []uint32{1, 2}) {
		t.Errorf("out at 3000: got %v, want [1 2]", got)
	}
}

func TestTimedSemaphoreFlushSendsEveryWaitingRelease(t *testing.T) {
	var q timedSemaphoreQueue
	q.release(release(2000, 1), 1000)
	q.release(release(5000, 2), 1000)
	due := q.flush(true, 0, 3000)
	if !equalValues(values(due), []uint32{1, 2}) || len(q.pending) != 0 {
		t.Fatalf("flush: got out %v with %d waiting, want [1 2] with none waiting", values(due), len(q.pending))
	}
	if due[0].status != nvgpu.NV9074_NOTIFICATION_STATUS_DONE || due[1].status != nvgpu.NV9074_NOTIFICATION_STATUS_DONE_FLUSHED {
		t.Errorf("flush statuses: got %#x %#x, want DONE then DONE_FLUSHED", due[0].status, due[1].status)
	}
}

// A flush with a maximum flush time sends the releases at the head of the
// list that wait until at least that much past the flush, and stops at one
// that waits until earlier, as tsemaCtrlCmdFlush_IMPL() does.
func TestTimedSemaphoreFlushKeepsReleasesWithinMaxFlushTime(t *testing.T) {
	var q timedSemaphoreQueue
	q.release(release(1900, 1), 1000)
	q.release(release(2500, 2), 1000)
	due := q.flush(true, 1000, 1000)
	if len(due) != 0 || len(q.pending) != 2 {
		t.Errorf("flush: got out %v with %d waiting, want none out with 2 waiting", values(due), len(q.pending))
	}
}

func TestTimedSemaphoreFlushSendsReleasesPastMaxFlushTime(t *testing.T) {
	var q timedSemaphoreQueue
	q.release(release(2500, 1), 1000)
	q.release(release(1900, 2), 1000)
	due := q.flush(true, 1000, 1000)
	if !equalValues(values(due), []uint32{1}) || len(q.pending) != 1 {
		t.Errorf("flush: got out %v with %d waiting, want [1] with 1 waiting", values(due), len(q.pending))
	}
}

func TestTimedSemaphoreReleaseWhileFlushingGoesOutAtOnce(t *testing.T) {
	var q timedSemaphoreQueue
	q.flush(true, 0, 1000)
	due, ok := q.release(release(1500, 1), 1000)
	if !ok || len(due) != 1 || due[0].status != nvgpu.NV9074_NOTIFICATION_STATUS_DONE_FLUSHED {
		t.Errorf("release while flushing: got out %v admitted %v, want [1] DONE_FLUSHED", values(due), ok)
	}
}

func TestTimedSemaphoreFlushOffStopsFlushing(t *testing.T) {
	var q timedSemaphoreQueue
	q.flush(true, 0, 1000)
	q.flush(false, 0, 1000)
	if due, _ := q.release(release(1500, 1), 1000); len(due) != 0 {
		t.Errorf("release after flushing stopped: got out %v, want none", values(due))
	}
}

// timedSemaphoreTestClient returns a client with a device, a subdevice and
// a channel, and the nvproxy that owns it.
func timedSemaphoreTestClient(t *testing.T) (*nvproxy, *rootClient) {
	ctx := context.Background()
	nvp := &nvproxy{clients: make(map[nvgpu.Handle]*rootClient)}
	client := &rootClient{resources: make(map[nvgpu.Handle]*object)}
	clientH := nvgpu.Handle{Val: 0xc1d00001}
	nvp.objAdd(ctx, client, clientH, nvgpu.NV01_ROOT_CLIENT, client, nvgpu.Handle{})
	nvp.objAdd(ctx, client, nvgpu.Handle{Val: 1}, nvgpu.NV01_DEVICE_0, &miscObject{}, clientH)
	nvp.objAdd(ctx, client, nvgpu.Handle{Val: 2}, nvgpu.NV20_SUBDEVICE_0, &miscObject{}, nvgpu.Handle{Val: 1})
	nvp.objAdd(ctx, client, nvgpu.Handle{Val: 3}, nvgpu.TURING_CHANNEL_GPFIFO_A, &miscObject{}, nvgpu.Handle{Val: 1})
	return nvp, client
}

func allocTestTimedSemaphore(nvp *nvproxy, client *rootClient, parent, h uint32) (nvgpu.Handle, uint32) {
	p := nvgpu.NVOS64_PARAMETERS{
		HRoot:         client.handle,
		HObjectParent: nvgpu.Handle{Val: parent},
		HObjectNew:    nvgpu.Handle{Val: h},
		HClass:        nvgpu.GF100_TIMED_SEMAPHORE_SW,
	}
	status := allocTimedSemaphoreLocked(context.Background(), nvp, client, &p)
	return p.HObjectNew, status
}

func TestTimedSemaphoreAllocUnderChannel(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	h, status := allocTestTimedSemaphore(nvp, client, 3, 10)
	if status != nvgpu.NV_OK {
		t.Fatalf("alloc under channel: status %#x, want NV_OK", status)
	}
	ts, status := client.timedSemaphoreLocked(h)
	if ts == nil {
		t.Fatalf("control on the semaphore: status %#x, want a semaphore", status)
	}
	if ts.device.Val != 1 {
		t.Errorf("semaphore device %v, want 1", ts.device)
	}
}

func TestTimedSemaphoreAllocOutsideChannelFails(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	if _, status := allocTestTimedSemaphore(nvp, client, 1, 10); status != nvgpu.NV_ERR_INVALID_OBJECT_PARENT {
		t.Errorf("alloc under device: status %#x, want NV_ERR_INVALID_OBJECT_PARENT", status)
	}
}

func TestTimedSemaphoreAllocWithUsedHandleFails(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	if _, status := allocTestTimedSemaphore(nvp, client, 3, 2); status != nvgpu.NV_ERR_INSERT_DUPLICATE_NAME {
		t.Errorf("alloc with a used handle: status %#x, want NV_ERR_INSERT_DUPLICATE_NAME", status)
	}
}

func TestTimedSemaphoreAllocWithNoHandleGetsUnusedHandle(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	h1, _ := allocTestTimedSemaphore(nvp, client, 3, 0)
	h2, _ := allocTestTimedSemaphore(nvp, client, 3, 0)
	if h1.Val < timedSemaphoreHandleBase || h2.Val < timedSemaphoreHandleBase || h1 == h2 {
		t.Errorf("handles %v and %v, want two distinct handles from %#x", h1, h2, timedSemaphoreHandleBase)
	}
}

func TestTimedSemaphoreHandleIsUsedOnlyByNvproxy(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	h, _ := allocTestTimedSemaphore(nvp, client, 3, 10)
	if !client.usedOnlyByNvproxyLocked(h) || client.usedOnlyByNvproxyLocked(nvgpu.Handle{Val: 3}) {
		t.Errorf("only the semaphore's handle should be used only by nvproxy")
	}
}

func TestTimedSemaphoreFreeingChannelDropsWaitingReleases(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	h, _ := allocTestTimedSemaphore(nvp, client, 3, 10)
	ts, _ := client.timedSemaphoreLocked(h)
	ts.queue.release(release(2000, 1), 1000)
	nvp.objFree(context.Background(), client, nvgpu.Handle{Val: 3})
	if !ts.released || len(ts.queue.pending) != 0 {
		t.Errorf("after freeing the channel: released %v with %d waiting, want released with none", ts.released, len(ts.queue.pending))
	}
	if _, status := client.timedSemaphoreLocked(h); status != nvgpu.NV_ERR_INVALID_OBJECT_HANDLE {
		t.Errorf("control after freeing the channel: status %#x, want NV_ERR_INVALID_OBJECT_HANDLE", status)
	}
}

// RM does not know a semaphore's handle and can give it to an RM object,
// which then replaces the semaphore.
func TestTimedSemaphoreReplacedByRMObjectWithItsHandle(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	h, _ := allocTestTimedSemaphore(nvp, client, 3, 10)
	ts, _ := client.timedSemaphoreLocked(h)
	ts.queue.release(release(2000, 1), 1000)
	other := &miscObject{}
	nvp.objAdd(context.Background(), client, h, nvgpu.NV01_MEMORY_SYSTEM, other, nvgpu.Handle{Val: 1})
	if !ts.released || len(ts.queue.pending) != 0 || client.timedSemaphores != 0 {
		t.Errorf("replaced semaphore: released %v with %d waiting and %d counted, want released, none waiting, 0 counted", ts.released, len(ts.queue.pending), client.timedSemaphores)
	}
	nvp.objFree(context.Background(), client, nvgpu.Handle{Val: 3})
	if client.resources[h] != &other.object {
		t.Errorf("freeing the channel removed the RM object with the semaphore's old handle")
	}
}

func TestTimedSemaphoreIsNoDependency(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	h, _ := allocTestTimedSemaphore(nvp, client, 3, 10)
	ctx := context.Background()
	dependent := &miscObject{}
	nvp.objAdd(ctx, client, nvgpu.Handle{Val: 30}, nvgpu.NV01_MEMORY_SYSTEM, dependent, nvgpu.Handle{Val: 1}, h)
	nvp.objAdd(ctx, client, h, nvgpu.NV01_MEMORY_SYSTEM, &miscObject{}, nvgpu.Handle{Val: 1})
	if client.resources[nvgpu.Handle{Val: 30}] != &dependent.object {
		t.Errorf("replacing the semaphore freed an object that named it as a dependency")
	}
}

func TestTimedSemaphoreAllocWithRMGeneratedHandleFails(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	if _, status := allocTestTimedSemaphore(nvp, client, 3, rmHandleBase+5); status != nvgpu.NV_ERR_INVALID_OBJECT_HANDLE {
		t.Errorf("alloc with a handle RM generates: status %#x, want NV_ERR_INVALID_OBJECT_HANDLE", status)
	}
}

func TestTimedSemaphoreNoTargetThroughOtherObject(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	ctx := context.Background()
	nvp.objAdd(ctx, client, nvgpu.Handle{Val: 20}, nvgpu.NV01_CONTEXT_DMA, &miscObject{}, nvgpu.Handle{Val: 1})
	nvp.objAdd(ctx, client, nvgpu.Handle{Val: 21}, nvgpu.NV01_MEMORY_SYSTEM, &miscObject{}, nvgpu.Handle{Val: 1})
	client.recordKernelDMAMappingLocked(nvgpu.Handle{Val: 20}, nvgpu.Handle{Val: 21}, 0, 0x1000, 0x100000)
	client.recordCPUMappingLocked(&frontendFDMemmapFile{}, nvgpu.Handle{Val: 21}, 0, 0x1000)
	if _, _, ok := client.kernelMappedLocked(nvgpu.Handle{Val: 1}, nvgpu.Handle{}, 0x100000, 16); ok {
		t.Errorf("mapping through a context DMA found, want only virtual memory mappings")
	}
}

func TestTimedSemaphoreControlOnOtherObjectIsNotSupported(t *testing.T) {
	_, client := timedSemaphoreTestClient(t)
	if _, status := client.timedSemaphoreLocked(nvgpu.Handle{Val: 3}); status != nvgpu.NV_ERR_NOT_SUPPORTED {
		t.Errorf("control on a channel: status %#x, want NV_ERR_NOT_SUPPORTED", status)
	}
}

func TestTimedSemaphoreSubdeviceOfDevice(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	h, _ := allocTestTimedSemaphore(nvp, client, 3, 10)
	ts, _ := client.timedSemaphoreLocked(h)
	if sub, ok := ts.subdeviceLocked(); !ok || sub.Val != 2 {
		t.Errorf("subdevice %v %v, want 2", sub, ok)
	}
}

// mappedTestClient returns a client whose device 1 maps memory 21 at GPU
// address 0x100000 with a kernel mapping, from memory offset 0x1000 for
// 0x2000 bytes, and whose application maps memory offsets 0x1000 to 0x2000
// through cpu1 and 0x2000 to 0x3000 through cpu2.
func mappedTestClient(t *testing.T) (*nvproxy, *rootClient, *frontendFDMemmapFile, *frontendFDMemmapFile) {
	nvp, client := timedSemaphoreTestClient(t)
	ctx := context.Background()
	nvp.objAdd(ctx, client, nvgpu.Handle{Val: 20}, nvgpu.NV50_MEMORY_VIRTUAL, &miscObject{}, nvgpu.Handle{Val: 1})
	nvp.objAdd(ctx, client, nvgpu.Handle{Val: 21}, nvgpu.NV01_MEMORY_SYSTEM, &miscObject{}, nvgpu.Handle{Val: 1})
	client.recordKernelDMAMappingLocked(nvgpu.Handle{Val: 20}, nvgpu.Handle{Val: 21}, 0x1000, 0x2000, 0x100000)
	cpu1, cpu2 := &frontendFDMemmapFile{}, &frontendFDMemmapFile{}
	client.recordCPUMappingLocked(cpu1, nvgpu.Handle{Val: 21}, 0x1000, 0x1000)
	client.recordCPUMappingLocked(cpu2, nvgpu.Handle{Val: 21}, 0x2000, 0x1000)
	return nvp, client, cpu1, cpu2
}

func TestTimedSemaphoreTargetIsApplicationMapping(t *testing.T) {
	_, client, cpu1, cpu2 := mappedTestClient(t)
	for _, tc := range []struct {
		gpuVA  uint64
		wantMF *frontendFDMemmapFile
		wantOf uint64
	}{
		{0x100010, cpu1, 0x10},
		{0x101ff0, cpu2, 0xff0},
	} {
		mf, off, ok := client.kernelMappedLocked(nvgpu.Handle{Val: 1}, nvgpu.Handle{}, tc.gpuVA, 16)
		if !ok || mf != tc.wantMF || off != tc.wantOf {
			t.Errorf("GPU address %#x: got %p offset %#x found %v, want %p offset %#x", tc.gpuVA, mf, off, ok, tc.wantMF, tc.wantOf)
		}
	}
}

func TestTimedSemaphoreNoTargetOutsideKernelMapping(t *testing.T) {
	_, client, _, _ := mappedTestClient(t)
	for _, gpuVA := range []uint64{0xffff0, 0x101ff8, 0x102000} {
		if _, _, ok := client.kernelMappedLocked(nvgpu.Handle{Val: 1}, nvgpu.Handle{}, gpuVA, 16); ok {
			t.Errorf("GPU address %#x found, want none", gpuVA)
		}
	}
}

func TestTimedSemaphoreNoTargetOnOtherDevice(t *testing.T) {
	_, client, _, _ := mappedTestClient(t)
	if _, _, ok := client.kernelMappedLocked(nvgpu.Handle{Val: 5}, nvgpu.Handle{}, 0x100010, 16); ok {
		t.Errorf("mapping of device 1 found for device 5")
	}
}

func TestTimedSemaphoreNoTargetAfterUnmap(t *testing.T) {
	_, client, _, _ := mappedTestClient(t)
	client.forgetKernelDMAMappingLocked(nvgpu.Handle{Val: 20}, 0x100000)
	if _, _, ok := client.kernelMappedLocked(nvgpu.Handle{Val: 1}, nvgpu.Handle{}, 0x100010, 16); ok {
		t.Errorf("GPU address found after unmapping")
	}
}

// TestTimedSemaphoreDroppedMappingsReleaseTheirObjects checks that mapping
// records that nvproxy drops leave no references in the backing arrays of its
// record slices, so that freed objects and closed files can be collected.
func TestTimedSemaphoreDroppedMappingsReleaseTheirObjects(t *testing.T) {
	t.Run("unmap", func(t *testing.T) {
		_, client, _, _ := mappedTestClient(t)
		client.forgetKernelDMAMappingLocked(nvgpu.Handle{Val: 20}, 0x100000)
		if dropped := client.kernelDMAMappings[:1][0]; dropped != (kernelDMAMapping{}) {
			t.Errorf("unmapped kernel mapping record still holds %+v", dropped)
		}
	})
	t.Run("kernel mapping prune", func(t *testing.T) {
		nvp, client, _, _ := mappedTestClient(t)
		ctx := context.Background()
		nvp.objAdd(ctx, client, nvgpu.Handle{Val: 22}, nvgpu.NV50_MEMORY_VIRTUAL, &miscObject{}, nvgpu.Handle{Val: 1})
		nvp.objAdd(ctx, client, nvgpu.Handle{Val: 23}, nvgpu.NV01_MEMORY_SYSTEM, &miscObject{}, nvgpu.Handle{Val: 1})
		client.recordKernelDMAMappingLocked(nvgpu.Handle{Val: 22}, nvgpu.Handle{Val: 21}, 0, 0x1000, 0x200000)
		nvp.objFree(ctx, client, nvgpu.Handle{Val: 21})
		client.kernelDMAMappingsPruneAt = 2
		client.recordKernelDMAMappingLocked(nvgpu.Handle{Val: 22}, nvgpu.Handle{Val: 23}, 0, 0x1000, 0x300000)
		if dropped := client.kernelDMAMappings[:2][1]; dropped != (kernelDMAMapping{}) {
			t.Errorf("pruned kernel mapping record still holds %+v", dropped)
		}
	})
	t.Run("CPU mapping prune", func(t *testing.T) {
		_, client, cpu1, cpu2 := mappedTestClient(t)
		cpu1.closed, cpu2.closed = true, true
		client.cpuMappingsPruneAt = 2
		client.recordCPUMappingLocked(&frontendFDMemmapFile{}, nvgpu.Handle{Val: 21}, 0x3000, 0x1000)
		if dropped := client.cpuMappings[:2][1]; dropped != (cpuMapping{}) {
			t.Errorf("pruned CPU mapping record still holds %+v", dropped)
		}
	})
}

func TestTimedSemaphoreNoTargetAfterMemoryFree(t *testing.T) {
	nvp, client, _, _ := mappedTestClient(t)
	nvp.objFree(context.Background(), client, nvgpu.Handle{Val: 21})
	if _, _, ok := client.kernelMappedLocked(nvgpu.Handle{Val: 1}, nvgpu.Handle{}, 0x100010, 16); ok {
		t.Errorf("GPU address found after freeing the memory")
	}
}

func TestTimedSemaphoreNoTargetAfterMappingFileCloses(t *testing.T) {
	_, client, cpu1, _ := mappedTestClient(t)
	cpu1.closed = true
	if _, _, ok := client.kernelMappedLocked(nvgpu.Handle{Val: 1}, nvgpu.Handle{}, 0x100010, 16); ok {
		t.Errorf("GPU address found after its CPU mapping's file closed")
	}
}

func TestTimedSemaphoreTargetOfMappingMadeThroughSubdevice(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	ctx := context.Background()
	nvp.objAdd(ctx, client, nvgpu.Handle{Val: 20}, nvgpu.NV50_MEMORY_VIRTUAL, &miscObject{}, nvgpu.Handle{Val: 2})
	nvp.objAdd(ctx, client, nvgpu.Handle{Val: 21}, nvgpu.NV01_MEMORY_SYSTEM, &miscObject{}, nvgpu.Handle{Val: 1})
	client.recordKernelDMAMappingLocked(nvgpu.Handle{Val: 20}, nvgpu.Handle{Val: 21}, 0, 0x1000, 0x100000)
	cpu := &frontendFDMemmapFile{}
	client.recordCPUMappingLocked(cpu, nvgpu.Handle{Val: 21}, 0, 0x1000)
	if mf, _, ok := client.kernelMappedLocked(nvgpu.Handle{Val: 1}, nvgpu.Handle{}, 0x100000, 16); !ok || mf != cpu {
		t.Errorf("mapping of virtual memory under a subdevice not found for its device")
	}
}

// RM maps a CPU mapping from the start of the page that holds the offset
// asked for, so the file's offset 0 is that page.
func TestTimedSemaphoreTargetInMappingAtUnalignedOffset(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	ctx := context.Background()
	nvp.objAdd(ctx, client, nvgpu.Handle{Val: 20}, nvgpu.NV50_MEMORY_VIRTUAL, &miscObject{}, nvgpu.Handle{Val: 1})
	nvp.objAdd(ctx, client, nvgpu.Handle{Val: 21}, nvgpu.NV01_MEMORY_SYSTEM, &miscObject{}, nvgpu.Handle{Val: 1})
	client.recordKernelDMAMappingLocked(nvgpu.Handle{Val: 20}, nvgpu.Handle{Val: 21}, 0, 0x2000, 0x100000)
	cpu := &frontendFDMemmapFile{}
	client.recordCPUMappingLocked(cpu, nvgpu.Handle{Val: 21}, 0x1100, 0x800)
	if _, off, ok := client.kernelMappedLocked(nvgpu.Handle{Val: 1}, nvgpu.Handle{}, 0x101100, 16); !ok || off != 0x100 {
		t.Errorf("GPU address 0x101100: offset %#x found %v, want 0x100", off, ok)
	}
}

func TestTimedSemaphoresPerClientAreLimited(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	for i := 0; i < maxTimedSemaphoresPerClient; i++ {
		if _, status := allocTestTimedSemaphore(nvp, client, 3, 0); status != nvgpu.NV_OK {
			t.Fatalf("semaphore %d: status %#x, want NV_OK", i+1, status)
		}
	}
	if _, status := allocTestTimedSemaphore(nvp, client, 3, 0); status != nvgpu.NV_ERR_INSUFFICIENT_RESOURCES {
		t.Errorf("semaphore %d: status %#x, want NV_ERR_INSUFFICIENT_RESOURCES", maxTimedSemaphoresPerClient+1, status)
	}
}

func TestTimedSemaphoreFreeingReturnsItsSlot(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	for i := 0; i < maxTimedSemaphoresPerClient; i++ {
		allocTestTimedSemaphore(nvp, client, 3, 0)
	}
	nvp.objFree(context.Background(), client, nvgpu.Handle{Val: 3})
	nvp.objAdd(context.Background(), client, nvgpu.Handle{Val: 4}, nvgpu.TURING_CHANNEL_GPFIFO_A, &miscObject{}, nvgpu.Handle{Val: 1})
	if _, status := allocTestTimedSemaphore(nvp, client, 4, 0); status != nvgpu.NV_OK {
		t.Errorf("semaphore after freeing the channel: status %#x, want NV_OK", status)
	}
}

// A checkpoint must be able to save a sandbox that holds a semaphore.
func TestTimedSemaphoreIsRestorable(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	h, _ := allocTestTimedSemaphore(nvp, client, 3, 10)
	if _, ok := client.resources[h].impl.(restorableObjectImpl); !ok {
		t.Errorf("GF100_TIMED_SEMAPHORE_SW is not restorable")
	}
}

// vaSpaceTestClient returns a client whose device 1 maps GPU address 0x100000
// with a kernel mapping in VA space 40 to memory 21 through virtual memory 20,
// and in VA space 41 to memory 23 through virtual memory 22. The application
// maps memory 21 through mf40 and memory 23 through mf41.
func vaSpaceTestClient(t *testing.T) (*nvproxy, *rootClient, *frontendFDMemmapFile, *frontendFDMemmapFile) {
	nvp, client := timedSemaphoreTestClient(t)
	ctx := context.Background()
	mfs := []*frontendFDMemmapFile{{}, {}}
	for i, vaSpace := range []nvgpu.Handle{{Val: 40}, {Val: 41}} {
		virt, mem := nvgpu.Handle{Val: 20 + 2*uint32(i)}, nvgpu.Handle{Val: 21 + 2*uint32(i)}
		nvp.objAdd(ctx, client, vaSpace, nvgpu.FERMI_VASPACE_A, &miscObject{}, nvgpu.Handle{Val: 1})
		nvp.objAdd(ctx, client, virt, nvgpu.NV50_MEMORY_VIRTUAL, &miscObject{object: object{vaSpace: vaSpace}}, nvgpu.Handle{Val: 1}, vaSpace)
		nvp.objAdd(ctx, client, mem, nvgpu.NV01_MEMORY_SYSTEM, &miscObject{}, nvgpu.Handle{Val: 1})
		client.recordKernelDMAMappingLocked(virt, mem, 0, 0x1000, 0x100000)
		client.recordCPUMappingLocked(mfs[i], mem, 0, 0x1000)
	}
	return nvp, client, mfs[0], mfs[1]
}

func TestTimedSemaphoreTargetIsInChannelVASpace(t *testing.T) {
	_, client, mf40, mf41 := vaSpaceTestClient(t)
	for _, tc := range []struct {
		vaSpace uint32
		wantMF  *frontendFDMemmapFile
	}{
		{40, mf40},
		{41, mf41},
	} {
		if mf, _, ok := client.kernelMappedLocked(nvgpu.Handle{Val: 1}, nvgpu.Handle{Val: tc.vaSpace}, 0x100000, 16); !ok || mf != tc.wantMF {
			t.Errorf("VA space %d: got %p found %v, want %p", tc.vaSpace, mf, ok, tc.wantMF)
		}
	}
}

func TestTimedSemaphoreNoTargetInOtherVASpace(t *testing.T) {
	_, client, _, _ := vaSpaceTestClient(t)
	if _, _, ok := client.kernelMappedLocked(nvgpu.Handle{Val: 1}, nvgpu.Handle{}, 0x100000, 16); ok {
		t.Errorf("mapping in VA space 40 or 41 found for the default VA space")
	}
}

// A channel takes the VA space of its context share, or else of its channel
// group, or else the one it is allocated with.
func TestChannelVASpace(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	ctx := context.Background()
	nvp.objAdd(ctx, client, nvgpu.Handle{Val: 50}, nvgpu.KEPLER_CHANNEL_GROUP_A, &miscObject{object: object{vaSpace: nvgpu.Handle{Val: 40}}}, nvgpu.Handle{Val: 1})
	nvp.objAdd(ctx, client, nvgpu.Handle{Val: 51}, nvgpu.FERMI_CONTEXT_SHARE_A, &miscObject{object: object{vaSpace: nvgpu.Handle{Val: 41}}}, nvgpu.Handle{Val: 50})
	for _, tc := range []struct {
		name     string
		parent   uint32
		ctxShare uint32
		vaSpace  uint32
		want     uint32
	}{
		{"under device", 1, 0, 42, 42},
		{"under channel group", 50, 0, 0, 40},
		{"with context share", 50, 51, 0, 41},
		{"with context share RM allocated", 50, 0xcaf00001, 0, 40},
	} {
		if got := client.channelVASpaceLocked(nvgpu.Handle{Val: tc.parent}, nvgpu.Handle{Val: tc.ctxShare}, nvgpu.Handle{Val: tc.vaSpace}); got.Val != tc.want {
			t.Errorf("%s: VA space %v, want %d", tc.name, got, tc.want)
		}
	}
}

func TestTimedSemaphoreTakesChannelVASpace(t *testing.T) {
	nvp, client := timedSemaphoreTestClient(t)
	nvp.objAdd(context.Background(), client, nvgpu.Handle{Val: 4}, nvgpu.TURING_CHANNEL_GPFIFO_A, &miscObject{object: object{vaSpace: nvgpu.Handle{Val: 40}}}, nvgpu.Handle{Val: 1})
	h, status := allocTestTimedSemaphore(nvp, client, 4, 0)
	if status != nvgpu.NV_OK {
		t.Fatalf("alloc status %#x, want NV_OK", status)
	}
	if ts, _ := client.timedSemaphoreLocked(h); ts.vaSpace.Val != 40 {
		t.Errorf("semaphore VA space %v, want 40", ts.vaSpace)
	}
}
