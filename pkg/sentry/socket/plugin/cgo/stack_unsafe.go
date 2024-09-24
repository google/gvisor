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

//go:build network_plugins
// +build network_plugins

package cgo

/*
#include <stdlib.h>

// stack initialization operations
int plugin_initstack(char *init_str, int *fds, int num);
int plugin_preinitstack(int pid, char **init_str_ptr, int **fds, int *num);
*/
import "C"

import (
	"fmt"
	"unsafe"
)

// InitStack implements CGO wrapper for plugin_initstack.
func InitStack(initStr string, fds []int) error {
	cs := C.CString(initStr)
	defer C.free(unsafe.Pointer(cs))
	fdNum := len(fds)
	cfds := make([]C.int, fdNum)
	for i := 0; i < fdNum; i++ {
		cfds[i] = (C.int)(fds[i])
	}

	if ret := C.plugin_initstack(cs, (*C.int)(&cfds[0]), (C.int)(fdNum)); ret != 0 {
		return fmt.Errorf("failed to init stack, ret = %v", ret)
	}

	return nil
}

// PreInitStack implements CGO wrapper for plugin_preinitstack.
func PreInitStack(pid int) (string, []int, error) {
	var (
		cInitStr *C.char
		cFdArray *C.int
		num      C.int
	)

	if ret := C.plugin_preinitstack(
		C.int(pid),
		(**C.char)(unsafe.Pointer(&cInitStr)),
		(**C.int)(unsafe.Pointer(&cFdArray)),
		(*C.int)(unsafe.Pointer(&num))); ret != 0 {
		return "", nil, fmt.Errorf("failed to prepare init args for the stack, ret = %v", ret)
	}

	defer func() {
		C.free(unsafe.Pointer(cInitStr))
		C.free(unsafe.Pointer(cFdArray))
	}()

	initStr := C.GoString(cInitStr)
	fds := make([]int, int(num))
	cFds := unsafe.Slice(cFdArray, num)
	for i := 0; i < int(num); i++ {
		fds[i] = int(cFds[i])
	}
	return initStr, fds, nil
}
