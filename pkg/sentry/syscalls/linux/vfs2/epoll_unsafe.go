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

package vfs2

import (
	"reflect"
	"runtime"
	"unsafe"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/gohacks"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/usermem"
)

const sizeofEpollEvent = int(unsafe.Sizeof(linux.EpollEvent{}))

func copyOutEvents(t *kernel.Task, addr usermem.Addr, events []linux.EpollEvent) (int, error) {
	if len(events) == 0 {
		return 0, nil
	}
	// Cast events to a byte slice for copying.
	var eventBytes []byte
	eventBytesHdr := (*reflect.SliceHeader)(unsafe.Pointer(&eventBytes))
	eventBytesHdr.Data = uintptr(gohacks.Noescape(unsafe.Pointer(&events[0])))
	eventBytesHdr.Len = len(events) * sizeofEpollEvent
	eventBytesHdr.Cap = len(events) * sizeofEpollEvent
	copiedBytes, err := t.CopyOutBytes(addr, eventBytes)
	runtime.KeepAlive(events)
	copiedEvents := copiedBytes / sizeofEpollEvent // rounded down
	return copiedEvents, err
}
