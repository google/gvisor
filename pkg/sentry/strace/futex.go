// Copyright 2018 Google LLC
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

package strace

import (
	"gvisor.googlesource.com/gvisor/pkg/abi"
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

// FutexCmd are the possible futex(2) commands.
var FutexCmd = abi.ValueSet{
	linux.FUTEX_WAIT:            "FUTEX_WAIT",
	linux.FUTEX_WAKE:            "FUTEX_WAKE",
	linux.FUTEX_FD:              "FUTEX_FD",
	linux.FUTEX_REQUEUE:         "FUTEX_REQUEUE",
	linux.FUTEX_CMP_REQUEUE:     "FUTEX_CMP_REQUEUE",
	linux.FUTEX_WAKE_OP:         "FUTEX_WAKE_OP",
	linux.FUTEX_LOCK_PI:         "FUTEX_LOCK_PI",
	linux.FUTEX_UNLOCK_PI:       "FUTEX_UNLOCK_PI",
	linux.FUTEX_TRYLOCK_PI:      "FUTEX_TRYLOCK_PI",
	linux.FUTEX_WAIT_BITSET:     "FUTEX_WAIT_BITSET",
	linux.FUTEX_WAKE_BITSET:     "FUTEX_WAKE_BITSET",
	linux.FUTEX_WAIT_REQUEUE_PI: "FUTEX_WAIT_REQUEUE_PI",
	linux.FUTEX_CMP_REQUEUE_PI:  "FUTEX_CMP_REQUEUE_PI",
}

func futex(op uint64) string {
	cmd := op &^ (linux.FUTEX_PRIVATE_FLAG | linux.FUTEX_CLOCK_REALTIME)
	clockRealtime := (op & linux.FUTEX_CLOCK_REALTIME) == linux.FUTEX_CLOCK_REALTIME
	private := (op & linux.FUTEX_PRIVATE_FLAG) == linux.FUTEX_PRIVATE_FLAG

	s := FutexCmd.Parse(cmd)
	if clockRealtime {
		s += "|FUTEX_CLOCK_REALTIME"
	}
	if private {
		s += "|FUTEX_PRIVATE_FLAG"
	}
	return s
}
