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

//go:build !false && cgo && arm64
// +build !false,cgo,arm64

package cgoextras

/*
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>

// PR_PAC_SET_ENABLED_KEYS and key bits are defined in <linux/prctl.h> since
// Linux 5.13. Define them here in case the build environment has older kernel
// headers.
#ifndef PR_PAC_SET_ENABLED_KEYS
#define PR_PAC_SET_ENABLED_KEYS 60
#endif
#ifndef PR_PAC_APIAKEY
#define PR_PAC_APIAKEY (1UL << 0)
#define PR_PAC_APIBKEY (1UL << 1)
#define PR_PAC_APDAKEY (1UL << 2)
#define PR_PAC_APDBKEY (1UL << 3)
#endif

__attribute__((constructor)) static void disable_host_pac(void) {
	const unsigned long keys =
		PR_PAC_APIAKEY | PR_PAC_APIBKEY | PR_PAC_APDAKEY | PR_PAC_APDBKEY;
	if (prctl(PR_PAC_SET_ENABLED_KEYS, keys, 0, 0, 0) != 0 && errno != EINVAL) {
		perror("prctl(PR_PAC_SET_ENABLED_KEYS) failed");
		abort();
	}
}
*/
import "C"
