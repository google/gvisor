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

package amdgpuproxy

import (
	"time"

	"gvisor.dev/gvisor/pkg/abi/amdgpu"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/marshal"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// maxGPUs bounds per-GPU arrays copied for an ioctl.
const maxGPUs = 256

type ioctlArgs interface {
	marshal.Marshallable
	CopyIn(marshal.CopyContext, hostarch.Addr) (int, error)
	CopyOut(marshal.CopyContext, hostarch.Addr) (int, error)
}

// call forwards cmd with argument v, updating v with the driver's output.
func (fd *deviceFD) call(cmd uint32, v marshal.Marshallable, nested ...[]byte) error {
	b := make([]byte, v.SizeBytes())
	v.MarshalBytes(b)
	err := hostIoctl(fd.hostFD, cmd, b, nested...)
	v.UnmarshalBytes(b)
	return err
}

// copyOut writes v back to the application if cmd has output and returns
// err, the driver's result. Like kfd_ioctl, output is copied even for a
// failed request.
func copyOut(t *kernel.Task, cmd uint32, addr hostarch.Addr, v ioctlArgs, err error) error {
	if cmd&(linux.IOC_READ<<linux.IOC_DIRSHIFT) != 0 {
		if _, cerr := v.CopyOut(t, addr); cerr != nil {
			return cerr
		}
	}
	return err
}

// gpuIoctl forwards an ioctl whose argument v names the GPU *gpuID.
func (fd *deviceFD) gpuIoctl(t *kernel.Task, cmd uint32, addr hostarch.Addr, v ioctlArgs, gpuID *uint32) error {
	if _, err := v.CopyIn(t, addr); err != nil {
		return err
	}
	if !fd.dev.proxy.gpus[*gpuID] {
		return linuxerr.EINVAL
	}
	return copyOut(t, cmd, addr, v, fd.call(cmd, v))
}

// passthrough forwards an ioctl whose argument needs no translation.
func (fd *deviceFD) passthrough(t *kernel.Task, cmd uint32, addr hostarch.Addr) error {
	b := make([]byte, linux.IOC_SIZE(cmd))
	if cmd&(linux.IOC_WRITE<<linux.IOC_DIRSHIFT) != 0 {
		if _, err := t.CopyInBytes(addr, b); err != nil {
			return err
		}
	}
	err := hostIoctl(fd.hostFD, cmd, b)
	if cmd&(linux.IOC_READ<<linux.IOC_DIRSHIFT) != 0 {
		if _, cerr := t.CopyOutBytes(addr, b); cerr != nil {
			return cerr
		}
	}
	return err
}

func (fd *deviceFD) kfdIoctl(t *kernel.Task, cmd uint32, addr hostarch.Addr) error {
	switch cmd {
	case amdgpu.AMDKFD_IOC_GET_VERSION,
		amdgpu.AMDKFD_IOC_DESTROY_QUEUE,
		amdgpu.AMDKFD_IOC_GET_CLOCK_COUNTERS,
		amdgpu.AMDKFD_IOC_DESTROY_EVENT,
		amdgpu.AMDKFD_IOC_SET_EVENT,
		amdgpu.AMDKFD_IOC_RUNTIME_ENABLE:
		// These arguments hold handles and scalars only. RUNTIME_ENABLE's
		// r_debug is a cookie kept for debuggers; the driver never
		// dereferences it.
		return fd.passthrough(t, cmd, addr)
	case amdgpu.AMDKFD_IOC_SET_MEMORY_POLICY:
		var v amdgpu.KFDSetMemoryPolicy
		return fd.gpuIoctl(t, cmd, addr, &v, &v.GPUID)
	case amdgpu.AMDKFD_IOC_SET_SCRATCH_BACKING_VA:
		var v amdgpu.KFDSetScratchBackingVA
		return fd.gpuIoctl(t, cmd, addr, &v, &v.GPUID)
	case amdgpu.AMDKFD_IOC_SET_TRAP_HANDLER:
		var v amdgpu.KFDSetTrapHandler
		return fd.gpuIoctl(t, cmd, addr, &v, &v.GPUID)
	case amdgpu.AMDKFD_IOC_AVAILABLE_MEMORY:
		var v amdgpu.KFDAvailableMemory
		return fd.gpuIoctl(t, cmd, addr, &v, &v.GPUID)
	case amdgpu.AMDKFD_IOC_CREATE_QUEUE:
		return fd.createQueue(t, addr)
	case amdgpu.AMDKFD_IOC_CREATE_EVENT:
		return fd.createEvent(t, addr)
	case amdgpu.AMDKFD_IOC_SET_XNACK_MODE:
		return fd.setXNACKMode(t, addr)
	case amdgpu.AMDKFD_IOC_GET_PROCESS_APERTURES_NEW:
		return fd.getProcessApertures(t, addr)
	case amdgpu.AMDKFD_IOC_ACQUIRE_VM:
		return fd.acquireVM(t, addr)
	case amdgpu.AMDKFD_IOC_ALLOC_MEMORY_OF_GPU:
		return fd.allocMemory(t, addr)
	case amdgpu.AMDKFD_IOC_FREE_MEMORY_OF_GPU:
		return fd.freeMemory(t, addr)
	case amdgpu.AMDKFD_IOC_MAP_MEMORY_TO_GPU, amdgpu.AMDKFD_IOC_UNMAP_MEMORY_FROM_GPU:
		return fd.mapMemory(t, cmd, addr)
	case amdgpu.AMDKFD_IOC_WAIT_EVENTS:
		return fd.waitEvents(t, addr)
	default:
		return linuxerr.ENOTTY
	}
}

func (fd *deviceFD) createQueue(t *kernel.Task, addr hostarch.Addr) error {
	var v amdgpu.KFDCreateQueue
	if _, err := v.CopyIn(t, addr); err != nil {
		return err
	}
	// Compute queue addresses are GPU virtual addresses. SDMA queues are
	// excluded because the driver's sdma_activity sysfs statistic reads
	// their read pointer as a CPU address of the KFD process, the sentry.
	if v.QueueType != amdgpu.KFD_IOC_QUEUE_TYPE_COMPUTE && v.QueueType != amdgpu.KFD_IOC_QUEUE_TYPE_COMPUTE_AQL {
		return linuxerr.EINVAL
	}
	if !fd.dev.proxy.gpus[v.GPUID] {
		return linuxerr.EINVAL
	}
	return copyOut(t, amdgpu.AMDKFD_IOC_CREATE_QUEUE, addr, &v, fd.call(amdgpu.AMDKFD_IOC_CREATE_QUEUE, &v))
}

// createEvent checks that an application-supplied signal page holds the
// KFD_SIGNAL_EVENT_LIMIT slots the driver initializes in it; not every driver
// release checks this itself.
func (fd *deviceFD) createEvent(t *kernel.Task, addr hostarch.Addr) error {
	const cmd = amdgpu.AMDKFD_IOC_CREATE_EVENT
	var v amdgpu.KFDCreateEvent
	if _, err := v.CopyIn(t, addr); err != nil {
		return err
	}
	if v.EventPageOffset != 0 {
		p := fd.dev.proxy
		p.mu.Lock()
		a := p.allocations[v.EventPageOffset]
		p.mu.Unlock()
		if a == nil || a.size < amdgpu.KFD_SIGNAL_EVENT_LIMIT*8 {
			return linuxerr.EINVAL
		}
	}
	return copyOut(t, cmd, addr, &v, fd.call(cmd, &v))
}

func (fd *deviceFD) setXNACKMode(t *kernel.Task, addr hostarch.Addr) error {
	var v amdgpu.KFDSetXNACKMode
	if _, err := v.CopyIn(t, addr); err != nil {
		return err
	}
	// XNACK was turned off by OpenKFD and must stay off. Negative values
	// query the current mode.
	if v.XNACKEnabled > 0 {
		return linuxerr.EPERM
	}
	return copyOut(t, amdgpu.AMDKFD_IOC_SET_XNACK_MODE, addr, &v, fd.call(amdgpu.AMDKFD_IOC_SET_XNACK_MODE, &v))
}

// getProcessApertures returns the apertures of the granted GPUs. A request
// for zero nodes returns their number, as in the driver.
func (fd *deviceFD) getProcessApertures(t *kernel.Task, addr hostarch.Addr) error {
	const cmd = amdgpu.AMDKFD_IOC_GET_PROCESS_APERTURES_NEW
	var v amdgpu.KFDGetProcessApertures
	if _, err := v.CopyIn(t, addr); err != nil {
		return err
	}
	var all amdgpu.KFDGetProcessApertures
	if err := fd.call(cmd, &all); err != nil {
		return err
	}
	if all.NumOfNodes > maxGPUs {
		return linuxerr.EIO
	}
	var entry amdgpu.KFDProcessDeviceApertures
	size := entry.SizeBytes()
	buf := make([]byte, int(all.NumOfNodes)*size)
	if len(buf) != 0 {
		all.AperturesPtr = hostBufferPointer(buf)
		if err := fd.call(cmd, &all, buf); err != nil {
			return err
		}
	}
	var out []byte
	for i := 0; i < int(all.NumOfNodes) && (i+1)*size <= len(buf); i++ {
		entry.UnmarshalBytes(buf[i*size:])
		if fd.dev.proxy.gpus[entry.GPUID] {
			out = append(out, buf[i*size:(i+1)*size]...)
		}
	}
	n := uint32(len(out) / size)
	if v.NumOfNodes != 0 {
		n = min(n, v.NumOfNodes)
		if _, err := t.CopyOutBytes(hostarch.Addr(v.AperturesPtr), out[:int(n)*size]); err != nil {
			return err
		}
	}
	v.NumOfNodes = n
	return copyOut(t, cmd, addr, &v, nil)
}

func (fd *deviceFD) acquireVM(t *kernel.Task, addr hostarch.Addr) error {
	var v amdgpu.KFDAcquireVM
	if _, err := v.CopyIn(t, addr); err != nil {
		return err
	}
	f := t.GetFile(int32(v.DRMFD))
	if f == nil {
		return linuxerr.EINVAL
	}
	defer f.DecRef(t)
	render, ok := f.Impl().(*deviceFD)
	if !ok || render.dev.kfd || render.dev.gpuID != v.GPUID {
		return linuxerr.EINVAL
	}
	v.DRMFD = uint32(render.hostFD)
	return fd.call(amdgpu.AMDKFD_IOC_ACQUIRE_VM, &v)
}

func (fd *deviceFD) allocMemory(t *kernel.Task, addr hostarch.Addr) error {
	var v amdgpu.KFDAllocMemory
	if _, err := v.CopyIn(t, addr); err != nil {
		return err
	}
	if !fd.dev.proxy.gpus[v.GPUID] {
		return linuxerr.EINVAL
	}
	a := &allocation{size: v.Size, memType: hostarch.MemoryTypeUncached}
	if v.Flags&amdgpu.KFD_IOC_ALLOC_MEM_FLAGS_AQL_QUEUE_MEM != 0 {
		// The driver maps an AQL queue buffer twice over half the size.
		a.size >>= 1
	}
	userAddr := v.MmapOffset
	switch {
	case v.Flags&amdgpu.KFD_IOC_ALLOC_MEM_FLAGS_VRAM != 0:
		a.memType = hostarch.MemoryTypeWriteCombine
	case v.Flags&amdgpu.KFD_IOC_ALLOC_MEM_FLAGS_GTT != 0:
		a.memType = hostarch.MemoryTypeWriteBack
	case v.Flags&amdgpu.KFD_IOC_ALLOC_MEM_FLAGS_USERPTR != 0:
		// MmapOffset is the application address to register. The driver
		// keeps faulting it in through its MMU notifier for as long as the
		// allocation exists, so give it a sentry alias of pinned pages.
		um, err := pinUserMemory(t, v.MmapOffset, v.Size)
		if err != nil {
			return err
		}
		a.userptr = um
		v.MmapOffset = uint64(um.hostAddr)
	}
	p := fd.dev.proxy
	p.mu.Lock()
	defer p.mu.Unlock()
	err := fd.call(amdgpu.AMDKFD_IOC_ALLOC_MEMORY_OF_GPU, &v)
	if err != nil {
		if a.userptr != nil {
			a.userptr.release()
			v.MmapOffset = userAddr
		}
	} else {
		a.mmapOffset = v.MmapOffset
		p.allocations[v.Handle] = a
	}
	return copyOut(t, amdgpu.AMDKFD_IOC_ALLOC_MEMORY_OF_GPU, addr, &v, err)
}

func (fd *deviceFD) freeMemory(t *kernel.Task, addr hostarch.Addr) error {
	var v amdgpu.KFDFreeMemory
	if _, err := v.CopyIn(t, addr); err != nil {
		return err
	}
	p := fd.dev.proxy
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := fd.call(amdgpu.AMDKFD_IOC_FREE_MEMORY_OF_GPU, &v); err != nil {
		return err
	}
	if a := p.allocations[v.Handle]; a != nil {
		if a.userptr != nil {
			a.userptr.release()
		}
		delete(p.allocations, v.Handle)
	}
	return nil
}

func (fd *deviceFD) mapMemory(t *kernel.Task, cmd uint32, addr hostarch.Addr) error {
	var v amdgpu.KFDMapMemory
	if _, err := v.CopyIn(t, addr); err != nil {
		return err
	}
	if v.NDevices > maxGPUs {
		return linuxerr.EINVAL
	}
	ids := make([]byte, 4*int(v.NDevices))
	ptr := v.DeviceIDsArrayPtr
	if _, err := t.CopyInBytes(hostarch.Addr(ptr), ids); err != nil {
		return err
	}
	for i := 0; i < len(ids); i += 4 {
		if !fd.dev.proxy.gpus[hostarch.ByteOrder.Uint32(ids[i:])] {
			return linuxerr.EINVAL
		}
	}
	v.DeviceIDsArrayPtr = hostBufferPointer(ids)
	err := fd.call(cmd, &v, ids)
	v.DeviceIDsArrayPtr = ptr
	return copyOut(t, cmd, addr, &v, err)
}

// waitEvents forwards WAIT_EVENTS as a sequence of bounded host waits, so
// that the task remains interruptible.
func (fd *deviceFD) waitEvents(t *kernel.Task, addr hostarch.Addr) error {
	var v amdgpu.KFDWaitEvents
	if _, err := v.CopyIn(t, addr); err != nil {
		return err
	}
	if v.NumEvents > amdgpu.KFD_SIGNAL_EVENT_LIMIT {
		return linuxerr.EINVAL
	}
	// Each host wait re-arms its waiters, which consumes pending auto-reset
	// signals, so waiting for all of several events cannot be split up.
	if v.WaitForAll != 0 && v.NumEvents > 1 {
		return linuxerr.EINVAL
	}
	var event amdgpu.KFDEventData
	events := make([]byte, int(v.NumEvents)*event.SizeBytes())
	ptr, timeout := v.EventsPtr, v.Timeout
	if _, err := t.CopyInBytes(hostarch.Addr(ptr), events); err != nil {
		return err
	}
	v.EventsPtr = hostBufferPointer(events)
	var deadline time.Time
	if timeout != amdgpu.KFD_EVENT_TIMEOUT_INFINITE {
		deadline = time.Now().Add(time.Duration(min(timeout, 0x7fffffff)) * time.Millisecond)
	}
	var err error
	for {
		wait := 50 * time.Millisecond
		if !deadline.IsZero() {
			wait = max(min(wait, time.Until(deadline)), 0)
		}
		v.Timeout = uint32((wait + time.Millisecond - 1) / time.Millisecond)
		err = fd.call(amdgpu.AMDKFD_IOC_WAIT_EVENTS, &v, events)
		if err != nil || v.WaitResult != amdgpu.KFD_IOC_WAIT_RESULT_TIMEOUT || (!deadline.IsZero() && !time.Now().Before(deadline)) {
			break
		}
		if t.Interrupted() {
			err = linuxerr.ERESTARTSYS
			break
		}
	}
	v.EventsPtr, v.Timeout = ptr, timeout
	if err == nil && v.WaitResult == amdgpu.KFD_IOC_WAIT_RESULT_COMPLETE {
		_, err = t.CopyOutBytes(hostarch.Addr(ptr), events)
	}
	if err != nil {
		v.WaitResult = amdgpu.KFD_IOC_WAIT_RESULT_FAIL
		// As the driver does when interrupted by a signal: the restarted
		// call gets the remaining timeout.
		if linuxerr.Equals(linuxerr.ERESTARTSYS, err) && !deadline.IsZero() {
			v.Timeout = uint32(max(time.Until(deadline), 0) / time.Millisecond)
		}
	}
	return copyOut(t, amdgpu.AMDKFD_IOC_WAIT_EVENTS, addr, &v, err)
}
