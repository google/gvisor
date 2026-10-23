// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cgroup

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// bpf calls bpf(2) with the attribute struct at attr. The kernel treats the
// part of struct bpf_attr beyond size as zero.
func bpf(cmd int, attr unsafe.Pointer, size uintptr) (int, error) {
	for {
		fd, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
		if errno == unix.EAGAIN && cmd == unix.BPF_PROG_LOAD {
			// A signal interrupted the verifier.
			continue
		}
		if errno != 0 {
			return -1, errno
		}
		return int(fd), nil
	}
}

// bpfProgLoad loads insns as a BPF_PROG_TYPE_CGROUP_DEVICE program and
// returns its FD.
func bpfProgLoad(insns []insn) (int, error) {
	license := []byte("Apache\x00")
	attr := struct {
		progType uint32
		insnCnt  uint32
		insns    uint64
		license  uint64
	}{
		progType: unix.BPF_PROG_TYPE_CGROUP_DEVICE,
		insnCnt:  uint32(len(insns)),
		insns:    uint64(uintptr(unsafe.Pointer(&insns[0]))),
		license:  uint64(uintptr(unsafe.Pointer(&license[0]))),
	}
	fd, err := bpf(unix.BPF_PROG_LOAD, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(insns)
	runtime.KeepAlive(license)
	return fd, err
}

// bpfProgAttach attaches the device filter prog to the cgroup at target,
// alongside the other filters attached to it, or in place of the filter
// replace if it is not -1.
func bpfProgAttach(target, prog, replace int) error {
	attr := struct {
		targetFD     uint32
		attachBpfFD  uint32
		attachType   uint32
		attachFlags  uint32
		replaceBpfFD uint32
	}{
		targetFD:    uint32(target),
		attachBpfFD: uint32(prog),
		attachType:  unix.BPF_CGROUP_DEVICE,
		attachFlags: unix.BPF_F_ALLOW_MULTI,
	}
	if replace >= 0 {
		attr.attachFlags |= unix.BPF_F_REPLACE
		attr.replaceBpfFD = uint32(replace)
	}
	_, err := bpf(unix.BPF_PROG_ATTACH, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return err
}

// bpfProgDetach detaches the device filter prog from the cgroup at target.
func bpfProgDetach(target, prog int) error {
	attr := struct {
		targetFD    uint32
		attachBpfFD uint32
		attachType  uint32
	}{
		targetFD:    uint32(target),
		attachBpfFD: uint32(prog),
		attachType:  unix.BPF_CGROUP_DEVICE,
	}
	_, err := bpf(unix.BPF_PROG_DETACH, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	return err
}

// bpfProgQuery returns the IDs of the device filters attached to the cgroup
// at target.
func bpfProgQuery(target int) ([]uint32, error) {
	// A cgroup holds at most BPF_CGROUP_MAX_PROGS (64) filters.
	ids := make([]uint32, 64)
	attr := struct {
		targetFD    uint32
		attachType  uint32
		queryFlags  uint32
		attachFlags uint32
		progIDs     uint64
		progCnt     uint32
		_           uint32
		// Linux 6.17 to 7.1 write the fields below regardless of the size
		// passed, so they must exist.
		progAttachFlags uint64
		linkIDs         uint64
		linkAttachFlags uint64
		revision        uint64
	}{
		targetFD:   uint32(target),
		attachType: unix.BPF_CGROUP_DEVICE,
		progIDs:    uint64(uintptr(unsafe.Pointer(&ids[0]))),
		progCnt:    uint32(len(ids)),
	}
	_, err := bpf(unix.BPF_PROG_QUERY, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
	runtime.KeepAlive(ids)
	if err != nil {
		return nil, err
	}
	return ids[:attr.progCnt], nil
}

// bpfProgGetFDByID returns an FD for the BPF program with the given ID.
func bpfProgGetFDByID(id uint32) (int, error) {
	attr := struct{ id uint32 }{id}
	return bpf(unix.BPF_PROG_GET_FD_BY_ID, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
}
