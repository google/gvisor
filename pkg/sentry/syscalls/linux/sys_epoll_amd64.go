// Copyright 2019 The gVisor Authors.
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

// +build amd64 i386

package linux

import (
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/epoll"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
)

// LINT.IfChange

// copyOutEvents copies epoll events from the kernel to user memory.
func copyOutEvents(t *kernel.Task, addr usermem.Addr, e []epoll.Event) error {
	const itemLen = 12
	buffLen := len(e) * itemLen
	if _, ok := addr.AddLength(uint64(buffLen)); !ok {
		return syserror.EFAULT
	}

	b := t.CopyScratchBuffer(buffLen)
	for i := range e {
		usermem.ByteOrder.PutUint32(b[i*itemLen:], e[i].Events)
		usermem.ByteOrder.PutUint32(b[i*itemLen+4:], uint32(e[i].Data[0]))
		usermem.ByteOrder.PutUint32(b[i*itemLen+8:], uint32(e[i].Data[1]))
	}

	if _, err := t.CopyOutBytes(addr, b); err != nil {
		return err
	}

	return nil
}

// LINT.ThenChange(vfs2/epoll.go)
