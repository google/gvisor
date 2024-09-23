// Copyright 2023 The gVisor Authors.
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

package stack

import (
	"sync"
	"syscall"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/safemem"
	"gvisor.dev/gvisor/pkg/sentry/socket/plugin/cgo"
)

type pluginStackRW struct {
	handle uint32

	// Represent both input and output flags.
	flags uint32

	// Reused as msg_control for read.
	to []byte

	iovs [3]syscall.Iovec
}

var pluginStackRWPool = sync.Pool{
	New: func() any {
		return &pluginStackRW{}
	},
}

func getReadWriter(handle uint32) *pluginStackRW {
	rw := pluginStackRWPool.Get().(*pluginStackRW)
	rw.handle = handle
	return rw
}

func putReadWriter(rw *pluginStackRW) {
	*rw = pluginStackRW{}
	pluginStackRWPool.Put(rw)
}

// ReadToBlocks implements safemem.Reader.ReadToBlocks.
func (rw *pluginStackRW) ReadToBlocks(dsts safemem.BlockSeq) (uint64, error) {
	// Set MSG_DONTWAIT flag to avoid blocking in plugin stack.
	flags := int(rw.flags) & ^linux.MSG_DONTWAIT
	if len(rw.to) != 0 || flags != 0 {
		iovs := iovecsFromBlockSeq(dsts, rw)
		rc, _, lc, mflags := cgo.Recvmsg(rw.handle, iovs, nil, rw.to, int(rw.flags))
		if rc >= 0 {
			rw.to = rw.to[:lc]
			rw.flags = uint32(mflags)
		}
		return translateReturn(rc)
	}

	var rc int64
	if dsts.IsEmpty() {
		rc = 0
	} else if dsts.NumBlocks() == 1 {
		rc = cgo.Read(rw.handle, dsts.Head().Addr(), dsts.Head().Len())
	} else {
		rc = cgo.Readv(rw.handle, iovecsFromBlockSeq(dsts, rw))
	}

	return translateReturn(rc)
}

// WriteFromBlocks implements safemem.Writer.WriteFromBlocks.
//
// Preconditions: rw.d.metadataMu must be locked.
func (rw *pluginStackRW) WriteFromBlocks(srcs safemem.BlockSeq) (uint64, error) {
	var rc int64

	if rw.to != nil {
		if srcs.IsEmpty() {
			// Invoke plugin stack checking whether there is any error to report
			// on target socket which sends 0-length data.
			rc = cgo.Sendto(rw.handle, 0, 0, 0, rw.to)
		} else if srcs.NumBlocks() == 1 {
			rc = cgo.Sendto(rw.handle, srcs.Head().Addr(), srcs.Head().Len(), 0, rw.to)
		} else {
			iovs := iovecsFromBlockSeq(srcs, rw)
			rc = cgo.Sendmsg(rw.handle, iovs, rw.to, 0)
		}
	} else {
		if srcs.IsEmpty() {
			// Invoke plugin stack checking whether there is any error to report
			// on target socket which sends 0-length data.
			rc = cgo.Write(rw.handle, 0, 0)
		} else if srcs.NumBlocks() == 1 {
			rc = cgo.Write(rw.handle, srcs.Head().Addr(), srcs.Head().Len())
		} else {
			rc = cgo.Writev(rw.handle, iovecsFromBlockSeq(srcs, rw))
		}
	}
	return translateReturn(rc)
}
