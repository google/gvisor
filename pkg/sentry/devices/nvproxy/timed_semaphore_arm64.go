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

package nvproxy

import "gvisor.dev/gvisor/pkg/hostarch"

// canSwapUint32 returns true if safecopy.SwapUint32 may store to memory of
// type t. On arm64 it is a load and store exclusive loop, and an exclusive
// store to uncached or write-combined memory may fail every time, so only
// write-back memory is written.
func canSwapUint32(t hostarch.MemoryType) bool {
	return t == hostarch.MemoryTypeWriteBack
}
