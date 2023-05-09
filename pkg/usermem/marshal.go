// Copyright 2021 The gVisor Authors.
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

package usermem

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// IOCopyContext wraps an object implementing hostarch.IO to implement
// marshal.CopyContext.
type IOCopyContext struct {
	Ctx  context.Context
	IO   IO
	Opts IOOpts
}

// CopyScratchBuffer implements marshal.CopyContext.CopyScratchBuffer.
func (i *IOCopyContext) CopyScratchBuffer(size int) []byte {
	return make([]byte, size)
}

// CopyOutBytes implements marshal.CopyContext.CopyOutBytes.
func (i *IOCopyContext) CopyOutBytes(addr hostarch.Addr, b []byte) (int, error) {
	return i.IO.CopyOut(i.Ctx, addr, b, i.Opts)
}

// CopyInBytes implements marshal.CopyContext.CopyInBytes.
func (i *IOCopyContext) CopyInBytes(addr hostarch.Addr, b []byte) (int, error) {
	return i.IO.CopyIn(i.Ctx, addr, b, i.Opts)
}
