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

//go:build amd64
// +build amd64

package slimvm

// SlimVM ioctls.
//
// Only the ioctls we need in Go appear here; some additional ioctls are used
// within the assembly stubs (KVM_INTERRUPT, etc.).
// 1. open(/dev/slimvm)
// 2. ioctl(_SLIMVM_CREATE_VCPU)
// 3. ioctl(_SLIMVM_RUN)
// 4. close(/dev/slimvm)
const (
	_SLIMVM_RUN          = 0x81f8e901
	_SLIMVM_SET_TSS_ADDR = 0xe907
	_SLIMVM_CREATE_VCPU  = 0xe908
	_SLIMVM_NMI          = 0xe90a
)
