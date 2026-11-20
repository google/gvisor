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

// Supported page sizes, used as threadMemLayouts indices.
const (
	pageSize4K = iota
	pageSize64K
	numPageSizes
)

// threadMemLayouts are the per-thread memory layouts for each supported page
// size. The Msg structure is stored in the last page of the shared stack.
var threadMemLayouts = [numPageSizes]threadMemLayout{
	pageSize4K: {
		memSize:                  8 << 12,
		guardSize:                1 << 12,
		privateStackOffset:       1 << 12,
		privateStackSize:         2 << 12,
		sharedStackSize:          4 << 12,
		sharedStackOffset:        4 << 12,
		msgOffsetFromSharedStack: 3 << 12,
	},
	pageSize64K: {
		memSize:                  5 << 16,
		guardSize:                1 << 16,
		privateStackOffset:       1 << 16,
		privateStackSize:         1 << 16,
		sharedStackSize:          2 << 16,
		sharedStackOffset:        3 << 16,
		msgOffsetFromSharedStack: 1 << 16,
	},
}

// hostThreadMemLayout returns the layout for the host page size, or an empty
// layout if it's unsupported (the Sentry doesn't start on such hosts).
func hostThreadMemLayout() threadMemLayout {
	switch hostarch.PageSize {
	case 1 << 12:
		return threadMemLayouts[pageSize4K]
	case 1 << 16:
		return threadMemLayouts[pageSize64K]
	default:
		return threadMemLayout{}
	}
}

// layout is the per-thread memory layout for the host page size. The Sentry
// passes it to the stub, see initStubArchGlobals.
var layout = hostThreadMemLayout()

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
	SpinningQueueMemSize = uintptr(hostarch.PageSize)
)

// LINT.ThenChange(sysmsg.h)
