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

//go:build pagesize_64k

package sysmsg

import (
	"gvisor.dev/gvisor/pkg/hostarch"
)

const (
	// PerThreadMemSize is the size of a per-thread memory region (320KB).
	PerThreadMemSize = 5 * hostarch.PageSize
	// GuardSize is the size of an unmapped region before the signal stack (64KB).
	GuardSize                   = hostarch.PageSize
	PerThreadPrivateStackOffset = GuardSize
	PerThreadPrivateStackSize   = 1 * hostarch.PageSize // 64KB (sufficient for syshandler private stack)
	// PerThreadSharedStackSize is the size of a per-thread stack region (128KB, includes stack + sysmsg).
	PerThreadSharedStackSize   = 2 * hostarch.PageSize
	PerThreadSharedStackOffset = 3 * hostarch.PageSize
)
