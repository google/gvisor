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

package linux

// From <linux/futex.h> and <sys/time.h>.
// Flags are used in syscall futex(2).
const (
	FUTEX_WAIT            = 0
	FUTEX_WAKE            = 1
	FUTEX_FD              = 2
	FUTEX_REQUEUE         = 3
	FUTEX_CMP_REQUEUE     = 4
	FUTEX_WAKE_OP         = 5
	FUTEX_LOCK_PI         = 6
	FUTEX_UNLOCK_PI       = 7
	FUTEX_TRYLOCK_PI      = 8
	FUTEX_WAIT_BITSET     = 9
	FUTEX_WAKE_BITSET     = 10
	FUTEX_WAIT_REQUEUE_PI = 11
	FUTEX_CMP_REQUEUE_PI  = 12

	FUTEX_PRIVATE_FLAG   = 128
	FUTEX_CLOCK_REALTIME = 256
)

// These are flags are from <linux/futex.h> and are used in FUTEX_WAKE_OP
// to define the operations.
const (
	FUTEX_OP_SET         = 0
	FUTEX_OP_ADD         = 1
	FUTEX_OP_OR          = 2
	FUTEX_OP_ANDN        = 3
	FUTEX_OP_XOR         = 4
	FUTEX_OP_OPARG_SHIFT = 8
	FUTEX_OP_CMP_EQ      = 0
	FUTEX_OP_CMP_NE      = 1
	FUTEX_OP_CMP_LT      = 2
	FUTEX_OP_CMP_LE      = 3
	FUTEX_OP_CMP_GT      = 4
	FUTEX_OP_CMP_GE      = 5
)

// FUTEX_TID_MASK is the TID portion of a PI futex word.
const FUTEX_TID_MASK = 0x3fffffff

// Constants used for priority-inheritance futexes.
const (
	FUTEX_WAITERS    = 0x80000000
	FUTEX_OWNER_DIED = 0x40000000
)

// FUTEX_BITSET_MATCH_ANY has all bits set.
const FUTEX_BITSET_MATCH_ANY = 0xffffffff

// ROBUST_LIST_LIMIT protects against a deliberately circular list.
const ROBUST_LIST_LIMIT = 2048

// RobustListHead corresponds to Linux's struct robust_list_head.
//
// +marshal
type RobustListHead struct {
	List          uint64
	FutexOffset   uint64
	ListOpPending uint64
}

// SizeOfRobustListHead is the size of a RobustListHead struct.
var SizeOfRobustListHead = (*RobustListHead)(nil).SizeBytes()
