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
	{
		Value: linux.FUTEX_WAIT,
		Name:  "FUTEX_WAIT",
	},
	{
		Value: linux.FUTEX_WAKE,
		Name:  "FUTEX_WAKE",
	},
	{
		Value: linux.FUTEX_FD,
		Name:  "FUTEX_FD",
	},
	{
		Value: linux.FUTEX_REQUEUE,
		Name:  "FUTEX_REQUEUE",
	},
	{
		Value: linux.FUTEX_CMP_REQUEUE,
		Name:  "FUTEX_CMP_REQUEUE",
	},
	{
		Value: linux.FUTEX_WAKE_OP,
		Name:  "FUTEX_WAKE_OP",
	},
	{
		Value: linux.FUTEX_LOCK_PI,
		Name:  "FUTEX_LOCK_PI",
	},
	{
		Value: linux.FUTEX_UNLOCK_PI,
		Name:  "FUTEX_UNLOCK_PI",
	},
	{
		Value: linux.FUTEX_TRYLOCK_PI,
		Name:  "FUTEX_TRYLOCK_PI",
	},
	{
		Value: linux.FUTEX_WAIT_BITSET,
		Name:  "FUTEX_WAIT_BITSET",
	},
	{
		Value: linux.FUTEX_WAKE_BITSET,
		Name:  "FUTEX_WAKE_BITSET",
	},
	{
		Value: linux.FUTEX_WAIT_REQUEUE_PI,
		Name:  "FUTEX_WAIT_REQUEUE_PI",
	},
	{
		Value: linux.FUTEX_CMP_REQUEUE_PI,
		Name:  "FUTEX_CMP_REQUEUE_PI",
	},
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
