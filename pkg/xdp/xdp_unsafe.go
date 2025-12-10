// Copyright 2022 The gVisor Authors.
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

package xdp

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/atomicbitops"
)

func registerUMEM(fd int, reg unix.XDPUmemReg) error {
	if _, _, errno := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), unix.SOL_XDP, unix.XDP_UMEM_REG, uintptr(unsafe.Pointer(&reg)), unsafe.Sizeof(reg), 0); errno != 0 {
		return fmt.Errorf("failed to setsockopt(XDP_UMEM_REG): errno %d", errno)
	}
	return nil
}

func getOffsets(fd int) (unix.XDPMmapOffsets, error) {
	var off unix.XDPMmapOffsets
	size := unsafe.Sizeof(off)
	if _, _, errno := unix.Syscall6(unix.SYS_GETSOCKOPT, uintptr(fd), unix.SOL_XDP, unix.XDP_MMAP_OFFSETS, uintptr(unsafe.Pointer(&off)), uintptr(unsafe.Pointer(&size)), 0); errno != 0 {
		return unix.XDPMmapOffsets{}, fmt.Errorf("failed to get offsets: %v", errno)
	} else if unsafe.Sizeof(off) != size {
		return unix.XDPMmapOffsets{}, fmt.Errorf("expected optlen of %d, but found %d", unsafe.Sizeof(off), size)
	}
	return off, nil
}

func sliceBackingPointer(slice []byte) uintptr {
	return uintptr(unsafe.Pointer(&slice[0]))
}

func sizeOfFillQueueDesc() uint64 {
	return uint64(unsafe.Sizeof(uint64(0)))
}

func sizeOfRXQueueDesc() uint64 {
	return uint64(unsafe.Sizeof(unix.XDPDesc{}))
}

func sizeOfCompletionQueueDesc() uint64 {
	return uint64(unsafe.Sizeof(uint64(0)))
}

func sizeOfTXQueueDesc() uint64 {
	return uint64(unsafe.Sizeof(unix.XDPDesc{}))
}

func (fq *FillQueue) init(off unix.XDPMmapOffsets, opts Opts) {
	base := unsafe.Pointer(&fq.mem[off.Fr.Desc])
	fq.ring = unsafe.Slice((*uint64)(base), int(opts.NDescriptors))
	fq.producer = (*atomicbitops.Uint32)(unsafe.Pointer(&fq.mem[off.Fr.Producer]))
	fq.consumer = (*atomicbitops.Uint32)(unsafe.Pointer(&fq.mem[off.Fr.Consumer]))
	fq.flags = (*atomicbitops.Uint32)(unsafe.Pointer(&fq.mem[off.Fr.Flags]))
}

func (rq *RXQueue) init(off unix.XDPMmapOffsets, opts Opts) {
	base := unsafe.Pointer(&rq.mem[off.Rx.Desc])
	rq.ring = unsafe.Slice((*unix.XDPDesc)(base), int(opts.NDescriptors))
	rq.producer = (*atomicbitops.Uint32)(unsafe.Pointer(&rq.mem[off.Rx.Producer]))
	rq.consumer = (*atomicbitops.Uint32)(unsafe.Pointer(&rq.mem[off.Rx.Consumer]))
	rq.flags = (*atomicbitops.Uint32)(unsafe.Pointer(&rq.mem[off.Rx.Flags]))
	// These probably don't have to be atomic, but we're only loading once
	// so better safe than sorry.
	rq.cachedProducer = rq.producer.Load()
	rq.cachedConsumer = rq.consumer.Load()
}

func (cq *CompletionQueue) init(off unix.XDPMmapOffsets, opts Opts) {
	base := unsafe.Pointer(&cq.mem[off.Cr.Desc])
	cq.ring = unsafe.Slice((*uint64)(base), int(opts.NDescriptors))
	cq.producer = (*atomicbitops.Uint32)(unsafe.Pointer(&cq.mem[off.Cr.Producer]))
	cq.consumer = (*atomicbitops.Uint32)(unsafe.Pointer(&cq.mem[off.Cr.Consumer]))
	cq.flags = (*atomicbitops.Uint32)(unsafe.Pointer(&cq.mem[off.Cr.Flags]))
	// These probably don't have to be atomic, but we're only loading once
	// so better safe than sorry.
	cq.cachedProducer = cq.producer.Load()
	cq.cachedConsumer = cq.consumer.Load()
}

func (tq *TXQueue) init(off unix.XDPMmapOffsets, opts Opts) {
	base := unsafe.Pointer(&tq.mem[off.Tx.Desc])
	tq.ring = unsafe.Slice((*unix.XDPDesc)(base), int(opts.NDescriptors))
	tq.producer = (*atomicbitops.Uint32)(unsafe.Pointer(&tq.mem[off.Tx.Producer]))
	tq.consumer = (*atomicbitops.Uint32)(unsafe.Pointer(&tq.mem[off.Tx.Consumer]))
	tq.flags = (*atomicbitops.Uint32)(unsafe.Pointer(&tq.mem[off.Tx.Flags]))
}

// kick notifies the kernel that there are packets to transmit.
func (tq *TXQueue) kick() error {
	if tq.flags.RacyLoad()&unix.XDP_RING_NEED_WAKEUP == 0 {
		return nil
	}

	var msg unix.Msghdr
	if _, _, errno := unix.Syscall6(unix.SYS_SENDMSG, uintptr(tq.sockfd), uintptr(unsafe.Pointer(&msg)), unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL, 0, 0, 0); errno != 0 {
		return fmt.Errorf("failed to kick TX queue via sendmsg: errno %d", errno)
	}
	return nil
}
