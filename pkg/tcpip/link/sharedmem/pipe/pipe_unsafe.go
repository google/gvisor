// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pipe

import (
	"sync/atomic"
	"unsafe"
)

func (p *pipe) write(idx uint64, v uint64) {
	ptr := (*uint64)(unsafe.Pointer(&p.buffer[idx&offsetMask:][:8][0]))
	*ptr = v
}

func (p *pipe) writeAtomic(idx uint64, v uint64) {
	ptr := (*uint64)(unsafe.Pointer(&p.buffer[idx&offsetMask:][:8][0]))
	atomic.StoreUint64(ptr, v)
}

func (p *pipe) readAtomic(idx uint64) uint64 {
	ptr := (*uint64)(unsafe.Pointer(&p.buffer[idx&offsetMask:][:8][0]))
	return atomic.LoadUint64(ptr)
}
