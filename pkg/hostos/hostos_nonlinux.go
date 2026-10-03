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

//go:build !linux

package hostos

import "errors"

// Stubbed out versions for non-Linux platforms, so that this package can still
// be compiled (and imported) on macOS and Windows.

var (
	errKernelVersion  = errors.New("hostos: KernelVersion is not supported on this platform")
	errTotalSystemMem = errors.New("hostos: TotalSystemMemory is not supported on this platform")
)

// KernelVersion is not supported on non-Linux platforms.
func KernelVersion() (Version, error) {
	return Version{}, errKernelVersion
}

// TotalSystemMemory is not supported on non-Linux platforms.
func TotalSystemMemory() (uint64, error) {
	return 0, errTotalSystemMem
}
