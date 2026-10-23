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

//go:build arm64

package sysmsg

import (
	"gvisor.dev/gvisor/pkg/hostarch"
)

// LINT.IfChange

// threadMemLayout describes the per-thread memory layout. See the diagram in
// sysmsg.go.
type threadMemLayout struct {
	memSize                  uintptr
	guardSize                uintptr
	privateStackOffset       uintptr
	privateStackSize         uintptr
	sharedStackSize          uintptr
	sharedStackOffset        uintptr
	msgOffsetFromSharedStack uintptr
}

// newThreadMemLayout returns the per-thread memory layout for the given page
// size. With bigger pages, the per-thread memory region can be composed of
// fewer pages and still fit everything:
//
//	                    4K pages   64K pages
//	memSize              8 pages    5 pages
//	guardSize            1 page     1 page
//	privateStackSize     2 pages    1 page
//	(guard)              1 page     1 page
//	sharedStackSize      4 pages    2 pages
func newThreadMemLayout(pageSize uintptr) threadMemLayout {
	l := threadMemLayout{
		memSize:          8 * pageSize,
		guardSize:        pageSize,
		privateStackSize: 2 * pageSize,
		sharedStackSize:  4 * pageSize,
	}
	if pageSize > 4096 {
		l.memSize = 5 * pageSize
		l.privateStackSize = pageSize
		l.sharedStackSize = 2 * pageSize
	}
	l.privateStackOffset = l.guardSize
	l.sharedStackOffset = l.memSize - l.sharedStackSize
	// The Msg structure is stored in the last page of the shared stack region.
	l.msgOffsetFromSharedStack = l.memSize - pageSize - l.sharedStackOffset
	return l
}

// layout is the per-thread memory layout for the host page size.
//
// On arm64, the page size is only known at runtime, so the layout is computed
// during package initialization. The stub reads it from variables that are
// set by the Sentry, see sysmsg.h:PER_THREAD_MEM_SIZE.
var layout = newThreadMemLayout(hostarch.PageSize)

// Per-thread memory layout. See the diagram in sysmsg.go.
var (
	// PerThreadMemSize is the size of a per-thread memory region (32KB with
	// 4K pages, 320KB with 64K pages).
	PerThreadMemSize = layout.memSize
	// GuardSize is the size of an unmapped region before the signal stack (one
	// page).
	GuardSize                   = layout.guardSize
	PerThreadPrivateStackOffset = layout.privateStackOffset
	PerThreadPrivateStackSize   = layout.privateStackSize
	// PerThreadSharedStackSize is the size of a per-thread stack region,
	// including the stack and the sysmsg (16KB with 4K pages, 128KB with 64K
	// pages).
	PerThreadSharedStackSize   = layout.sharedStackSize
	PerThreadSharedStackOffset = layout.sharedStackOffset

	// MsgOffsetFromSharedStack is the offset of the Msg structure on
	// the thread stack.
	MsgOffsetFromSharedStack = layout.msgOffsetFromSharedStack

	// SpinningQueueMemSize is the size of a spinning queue memory region.
	SpinningQueueMemSize = hostarch.PageSize
)

// LINT.ThenChange(sysmsg.h)
