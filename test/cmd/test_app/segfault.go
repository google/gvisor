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

package main

import (
	"context"
	"log"
	"os"
	"unsafe"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/flag"
)

// segfault restores the default action of SIGSEGV and then faults, so that
// SIGSEGV terminates the process.
type segfault struct{}

// Name implements subcommands.Command.Name.
func (*segfault) Name() string {
	return "segfault"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*segfault) Synopsis() string {
	return "restores the default action of SIGSEGV and faults, so that SIGSEGV terminates the process"
}

// Usage implements subcommands.Command.Usage.
func (*segfault) Usage() string {
	return "segfault"
}

// SetFlags implements subcommands.Command.SetFlags.
func (*segfault) SetFlags(*flag.FlagSet) {}

// Execute implements subcommands.Command.Execute.
func (*segfault) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	// The Go runtime installs its own SIGSEGV handler. A raw rt_sigaction(2)
	// restores the default action behind the runtime's back, so the fault
	// below terminates the process.
	var act struct {
		handler  uintptr
		flags    uint64
		restorer uintptr
		mask     uint64
	}
	if _, _, errno := unix.RawSyscall6(unix.SYS_RT_SIGACTION, uintptr(unix.SIGSEGV), uintptr(unsafe.Pointer(&act)), 0, 8 /* sizeof(sigset_t) */, 0, 0); errno != 0 {
		log.Fatalf("rt_sigaction(SIGSEGV, SIG_DFL) failed: %v", errno)
	}
	mem, err := unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_NONE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		log.Fatalf("mmap(PROT_NONE) failed: %v", err)
	}
	mem[0] = 1
	log.Fatalf("write to a PROT_NONE mapping did not fault")
	return subcommands.ExitFailure
}
