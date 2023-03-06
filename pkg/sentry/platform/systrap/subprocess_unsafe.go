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

//go:build go1.12
// +build go1.12

// //go:linkname directives type-checked by checklinkname. Any other
// non-linkname assumptions outside the Go 1 compatibility guarantee should
// have an accompanied vet check or version guard build tag.

package systrap

import (
	"unsafe"

	"gvisor.dev/gvisor/pkg/sentry/platform/systrap/sysmsg"
)

//go:linkname beforeFork syscall.runtime_BeforeFork
func beforeFork()

//go:linkname afterFork syscall.runtime_AfterFork
func afterFork()

//go:linkname afterForkInChild syscall.runtime_AfterForkInChild
func afterForkInChild()

// getThreadContextFromID returns a ThreadContext struct that corresponds to the
// given ID.
//
// Precondition: cid must be a valid thread context ID that has a mapping for it
// that exists in s.contexts.
func (s *subprocess) getThreadContextFromID(cid uint64) *sysmsg.ThreadContext {
	tcSlot := s.threadContextRegion + uintptr(cid)*sysmsg.AllocatedSizeofThreadContextStruct
	return (*sysmsg.ThreadContext)(unsafe.Pointer(tcSlot))
}
