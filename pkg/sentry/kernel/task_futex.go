// Copyright 2018 The gVisor Authors.
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
	"gvisor.dev/gvisor/pkg/sentry/kernel/futex"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

// Futex returns t's futex manager.
//
// Preconditions: The caller must be running on the task goroutine, or t.mu
// must be locked.
func (t *Task) Futex() *futex.Manager {
	return t.tc.fu
}

// SwapUint32 implements futex.Target.SwapUint32.
func (t *Task) SwapUint32(addr usermem.Addr, new uint32) (uint32, error) {
	return t.MemoryManager().SwapUint32(t, addr, new, usermem.IOOpts{
		AddressSpaceActive: true,
	})
}

// CompareAndSwapUint32 implemets futex.Target.CompareAndSwapUint32.
func (t *Task) CompareAndSwapUint32(addr usermem.Addr, old, new uint32) (uint32, error) {
	return t.MemoryManager().CompareAndSwapUint32(t, addr, old, new, usermem.IOOpts{
		AddressSpaceActive: true,
	})
}

// LoadUint32 implemets futex.Target.LoadUint32.
func (t *Task) LoadUint32(addr usermem.Addr) (uint32, error) {
	return t.MemoryManager().LoadUint32(t, addr, usermem.IOOpts{
		AddressSpaceActive: true,
	})
}

// GetSharedKey implements futex.Target.GetSharedKey.
func (t *Task) GetSharedKey(addr usermem.Addr) (futex.Key, error) {
	return t.MemoryManager().GetSharedFutexKey(t, addr)
}
