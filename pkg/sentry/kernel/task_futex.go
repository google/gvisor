// Copyright 2018 Google Inc.
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

package kernel

import (
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/futex"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Futex returns t's futex manager.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) Futex() *futex.Manager {
	return t.tc.fu
}

// FutexChecker returns a futex.Checker that interprets addresses in t's
// address space.
//
// Preconditions: All uses of the returned futex.Checker must be on the task
// goroutine.
func (t *Task) FutexChecker() futex.Checker {
	return futexChecker{t}
}

type futexChecker struct {
	t *Task
}

// Check implements futex.Checker.Check.
func (f futexChecker) Check(addr uintptr, val uint32) error {
	// FIXME
	in := f.t.CopyScratchBuffer(4)
	_, err := f.t.CopyInBytes(usermem.Addr(addr), in)
	if err != nil {
		return err
	}
	nval := usermem.ByteOrder.Uint32(in)
	if val != nval {
		return syserror.EAGAIN
	}
	return nil
}

func (f futexChecker) atomicOp(addr uintptr, op func(uint32) uint32) (uint32, error) {
	// FIXME
	in := f.t.CopyScratchBuffer(4)
	_, err := f.t.CopyInBytes(usermem.Addr(addr), in)
	if err != nil {
		return 0, err
	}
	o := usermem.ByteOrder.Uint32(in)
	mm := f.t.MemoryManager()
	for {
		n := op(o)
		r, err := mm.CompareAndSwapUint32(f.t, usermem.Addr(addr), o, n, usermem.IOOpts{
			AddressSpaceActive: true,
		})
		if err != nil {
			return 0, err
		}

		if r == o {
			return o, nil
		}
		o = r
	}
}

// Op implements futex.Checker.Op, interpreting opIn consistently with Linux.
func (f futexChecker) Op(addr uintptr, opIn uint32) (bool, error) {
	op := (opIn >> 28) & 0xf
	cmp := (opIn >> 24) & 0xf
	opArg := (opIn >> 12) & 0xfff
	cmpArg := opIn & 0xfff

	if op&linux.FUTEX_OP_OPARG_SHIFT != 0 {
		opArg = 1 << opArg
		op &^= linux.FUTEX_OP_OPARG_SHIFT // clear flag
	}

	var oldVal uint32
	var err error
	switch op {
	case linux.FUTEX_OP_SET:
		oldVal, err = f.t.MemoryManager().SwapUint32(f.t, usermem.Addr(addr), opArg, usermem.IOOpts{
			AddressSpaceActive: true,
		})
	case linux.FUTEX_OP_ADD:
		oldVal, err = f.atomicOp(addr, func(a uint32) uint32 {
			return a + opArg
		})
	case linux.FUTEX_OP_OR:
		oldVal, err = f.atomicOp(addr, func(a uint32) uint32 {
			return a | opArg
		})
	case linux.FUTEX_OP_ANDN:
		oldVal, err = f.atomicOp(addr, func(a uint32) uint32 {
			return a &^ opArg
		})
	case linux.FUTEX_OP_XOR:
		oldVal, err = f.atomicOp(addr, func(a uint32) uint32 {
			return a ^ opArg
		})
	default:
		return false, syserror.ENOSYS
	}
	if err != nil {
		return false, err
	}

	switch cmp {
	case linux.FUTEX_OP_CMP_EQ:
		return oldVal == cmpArg, nil
	case linux.FUTEX_OP_CMP_NE:
		return oldVal != cmpArg, nil
	case linux.FUTEX_OP_CMP_LT:
		return oldVal < cmpArg, nil
	case linux.FUTEX_OP_CMP_LE:
		return oldVal <= cmpArg, nil
	case linux.FUTEX_OP_CMP_GT:
		return oldVal > cmpArg, nil
	case linux.FUTEX_OP_CMP_GE:
		return oldVal >= cmpArg, nil
	default:
		return false, syserror.ENOSYS
	}
}

// GetSharedKey implements futex.Checker.GetSharedKey.
func (f futexChecker) GetSharedKey(addr uintptr) (futex.Key, error) {
	return f.t.MemoryManager().GetSharedFutexKey(f.t, usermem.Addr(addr))
}
