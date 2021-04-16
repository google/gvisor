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

package host

import (
	"fmt"
	"io"
	"sync/atomic"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/fdnotifier"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/hostfd"
)

// beforeSave is invoked by stateify.
func (i *inode) beforeSave() {
	if !i.savable {
		panic("host.inode is not savable")
	}
	if i.ftype == unix.S_IFIFO {
		// If this pipe FD is readable, drain it so that bytes in the pipe can
		// be read after restore. (This is a legacy VFS1 feature.) We don't
		// know if the pipe FD is readable, so just try reading and tolerate
		// EBADF from the read.
		i.bufMu.Lock()
		defer i.bufMu.Unlock()
		var buf [hostarch.PageSize]byte
		for {
			n, err := hostfd.Preadv2(int32(i.hostFD), safemem.BlockSeqOf(safemem.BlockFromSafeSlice(buf[:])), -1 /* offset */, 0 /* flags */)
			if n != 0 {
				i.buf = append(i.buf, buf[:n]...)
			}
			if err != nil {
				if err == io.EOF || err == unix.EAGAIN || err == unix.EBADF {
					break
				}
				panic(fmt.Errorf("host.inode.beforeSave: buffering from pipe failed: %v", err))
			}
		}
		if len(i.buf) != 0 {
			atomic.StoreUint32(&i.haveBuf, 1)
		}
	}
}

// afterLoad is invoked by stateify.
func (i *inode) afterLoad() {
	if i.mayBlock {
		if err := unix.SetNonblock(i.hostFD, true); err != nil {
			panic(fmt.Sprintf("host.inode.afterLoad: failed to set host FD %d non-blocking: %v", i.hostFD, err))
		}
		if err := fdnotifier.AddFD(int32(i.hostFD), &i.queue); err != nil {
			panic(fmt.Sprintf("host.inode.afterLoad: fdnotifier.AddFD(%d) failed: %v", i.hostFD, err))
		}
	}
}

// afterLoad is invoked by stateify.
func (c *ConnectedEndpoint) afterLoad() {
	if err := c.initFromOptions(); err != nil {
		panic(fmt.Sprintf("initFromOptions failed: %v", err))
	}
}
