// Copyright 2024 The gVisor Authors.
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

//go:build cgo && amd64
// +build cgo,amd64

package kvm

import (
	"gvisor.dev/gvisor/pkg/ring0"
)

func init() {
	// libc calls mmap with blocked signals. In this case, the mmap system call
	// can't be trapped with seccomp.
	forceMappingEntireAddressSpace = true
	// Limit the physical address space size to control the memory
	// overhead. It is about 3MB for 40 bits address space.
	ring0.PhysicalAddressBits = 40
}
