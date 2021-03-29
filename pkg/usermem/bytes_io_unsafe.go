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

package usermem

import (
	"sync/atomic"
	"unsafe"

	"gvisor.dev/gvisor/pkg/atomicbitops"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/hostarch"
)

// SwapUint32 implements IO.SwapUint32.
func (b *BytesIO) SwapUint32(ctx context.Context, addr hostarch.Addr, new uint32, opts IOOpts) (uint32, error) {
	if _, rngErr := b.rangeCheck(addr, 4); rngErr != nil {
		return 0, rngErr
	}
	return atomic.SwapUint32((*uint32)(unsafe.Pointer(&b.Bytes[int(addr)])), new), nil
}

// CompareAndSwapUint32 implements IO.CompareAndSwapUint32.
func (b *BytesIO) CompareAndSwapUint32(ctx context.Context, addr hostarch.Addr, old, new uint32, opts IOOpts) (uint32, error) {
	if _, rngErr := b.rangeCheck(addr, 4); rngErr != nil {
		return 0, rngErr
	}
	return atomicbitops.CompareAndSwapUint32((*uint32)(unsafe.Pointer(&b.Bytes[int(addr)])), old, new), nil
}

// LoadUint32 implements IO.LoadUint32.
func (b *BytesIO) LoadUint32(ctx context.Context, addr hostarch.Addr, opts IOOpts) (uint32, error) {
	if _, err := b.rangeCheck(addr, 4); err != nil {
		return 0, err
	}
	return atomic.LoadUint32((*uint32)(unsafe.Pointer(&b.Bytes[int(addr)]))), nil
}
