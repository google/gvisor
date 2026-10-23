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

package backtrace

/*
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

extern void rte_dump_stack(void);
extern int rte_openlog_stream(FILE *);

// Keep an observable caller without changing the archive's optimization flags.
static __attribute__((noinline)) int capture_stack(char **text) {
    size_t size;
    FILE *stream = open_memstream(text, &size);
    if (stream == NULL) {
        return -1;
    }
    rte_openlog_stream(stream);
    rte_dump_stack();
    rte_openlog_stream(NULL);
    return fclose(stream);
}
*/
import "C"

import "unsafe"

// dumpStack enters the actual DPDK archive through cgo, including the switch
// from Go's goroutine stack. A C-only test does not exercise that boundary.
func dumpStack() (string, error) {
	var text *C.char
	ret, err := C.capture_stack(&text)
	defer C.free(unsafe.Pointer(text))
	if ret != 0 {
		return "", err
	}
	return C.GoString(text), nil
}
