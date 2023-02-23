// Copyright 2020 The gVisor Authors.
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

//go:build arm64
// +build arm64

package usertrap

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/usermem"
)

// trapNR is the maximum number of traps what can fit in the trap table.
const trapNR = 256

// trapSize is the size of one trap.
const trapSize = 80

// TrapTableSize returns the maximum size of a trap table.
func TrapTableSize() uintptr {
	return uintptr(trapNR * trapSize)
}

type memoryManager interface {
	usermem.IO
	MMap(ctx context.Context, opts memmap.MMapOpts) (hostarch.Addr, error)
}

// State represents the current state of the trap table.
//
// +stateify savable
type State struct {
}

// New returns the new state structure.
func New() *State {
	return &State{}
}

func (*State) PatchSyscall(ctx context.Context, ac *arch.Context64, mm memoryManager) (restart bool, err error) {
	return false /* restart */, nil
}

// HandleFault handles a fault on a patched syscall instruction.
func (*State) HandleFault(ctx context.Context, ac *arch.Context64, mm memoryManager) error {
	return nil
}

// PreFork does nothing on arm64 as syscall trapping is not supported.
func (*State) PreFork() {
}

// PostFork does nothing on arm64 as syscall trapping is not supported.
func (*State) PostFork() {
}
