// Copyright 2016 The Netstack Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sharedmem

import (
	"unsafe"
)

// sharedDataPointer converts the shared data slice into a pointer so that it
// can be used in atomic operations.
func sharedDataPointer(sharedData []byte) *uint32 {
	return (*uint32)(unsafe.Pointer(&sharedData[0:4][0]))
}
