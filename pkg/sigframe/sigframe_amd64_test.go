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

//go:build amd64
// +build amd64

package sigframe

import (
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

func TestUserSignalHandler(t *testing.T) {
	addr, _, errno := unix.Syscall6(unix.SYS_MMAP, 0, hostarch.PageSize*4, uintptr(unix.PROT_READ|unix.PROT_WRITE),
		uintptr(unix.MAP_PRIVATE|unix.MAP_ANONYMOUS),
		0, 0)
	if errno != 0 {
		t.Fatalf("mmap failed: %v", errno)
	}
	t.Cleanup(func() {
		if _, _, errno := unix.Syscall(unix.SYS_MUNMAP, addr, hostarch.PageSize*4, 0); errno != 0 {
			t.Errorf("munmap failed: %v", errno)
		}
	})
	stack := linux.SignalStack{
		Addr: uint64(addr),
		Size: hostarch.PageSize * 4,
	}
	set := linux.MakeSignalSet(linux.SIGURG)
	if errno := CallWithSignalFrame(&stack, addrOfUserHandler(), &set, 0); errno != 0 {
		t.Fatalf("CallWithSignalFrame failed: %v", errno)
	}
}

func TestUserSignalHandlerSmallStack(t *testing.T) {
	var stack linux.SignalStack
	// Leave the thread's signal mask unchanged when setup fails.
	var set linux.SignalSet
	if errno := CallWithSignalFrame(&stack, addrOfUserHandler(), &set, 0); errno != unix.ENOMEM {
		t.Fatalf("CallWithSignalFrame returned %v, want ENOMEM", errno)
	}
}

func BenchmarkUserSigHandler(b *testing.B) {
	addr, _, errno := unix.Syscall6(unix.SYS_MMAP, 0, hostarch.PageSize*4, uintptr(unix.PROT_READ|unix.PROT_WRITE),
		uintptr(unix.MAP_PRIVATE|unix.MAP_ANONYMOUS),
		0, 0)
	if errno != 0 {
		b.Fatalf("mmap failed: %v", errno)
	}
	b.Cleanup(func() {
		if _, _, errno := unix.Syscall(unix.SYS_MUNMAP, addr, hostarch.PageSize*4, 0); errno != 0 {
			b.Errorf("munmap failed: %v", errno)
		}
	})
	stack := linux.SignalStack{
		Addr: uint64(addr),
		Size: hostarch.PageSize * 4,
	}
	set := linux.MakeSignalSet(linux.SIGURG)
	for i := 0; i < b.N; i++ {
		if errno := CallWithSignalFrame(&stack, addrOfUserHandler(), &set, 0); errno != 0 {
			b.Fatalf("CallWithSignalFrame failed: %v", errno)
		}
	}
}

func addrOfUserHandler() uintptr

func userHandler(sigframe *arch.UContext64) {
	Sigreturn(sigframe)
}
