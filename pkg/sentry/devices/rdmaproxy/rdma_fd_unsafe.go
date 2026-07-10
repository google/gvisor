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

package rdmaproxy

import (
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// rdmaWriteInvoke executes a uverbs legacy write() command on hostFD.
//
// If patchResp is true, the __u64 response pointer at respPtrOffset in buf
// is replaced with the address of respBuf's first byte (or 0 if respBuf is
// empty) before the buffer reaches the host, so the host kernel only ever
// writes the response into sentry memory; the caller is responsible for
// copying respBuf out to the application. The host kernel writes at most
// len(respBuf) bytes, since the buffer is sized exactly to the out_words
// the command requests.
func rdmaWriteInvoke(hostFD int32, buf []byte, respBuf []byte, patchResp bool) error {
	if patchResp {
		var respAddr uint64
		if len(respBuf) > 0 {
			respAddr = uint64(uintptr(unsafe.Pointer(&respBuf[0])))
		}
		hostarch.ByteOrder.PutUint64(buf[respPtrOffset:], respAddr)
	}
	n, _, errno := unix.Syscall(unix.SYS_WRITE, uintptr(hostFD), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	runtime.KeepAlive(respBuf)
	if errno != 0 {
		return errno
	}
	if n != uintptr(len(buf)) {
		// ib_uverbs_write() never returns a short count on success.
		return linuxerr.EIO
	}
	return nil
}
