// Copyright 2023 The gVisor Authors.
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

//go:build network_plugins
// +build network_plugins

package cgo

import (
	"unsafe"
)

// GetPtr gets []byte's start address and converts the address into
// unsafe.Pointer that will be used as C pointer.
func GetPtr(bs []byte) unsafe.Pointer {
	if len(bs) == 0 {
		return nil
	}
	return unsafe.Pointer(&bs[0])
}

func convertRetVal(ret int64, errno uint64) int64 {
	if ret < 0 {
		return -int64(errno)
	} else {
		return ret
	}
}
