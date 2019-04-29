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

// Resources for getrlimit(2)/setrlimit(2)/prlimit(2).
const (
	RLIMIT_CPU        = 0
	RLIMIT_FSIZE      = 1
	RLIMIT_DATA       = 2
	RLIMIT_STACK      = 3
	RLIMIT_CORE       = 4
	RLIMIT_RSS        = 5
	RLIMIT_NPROC      = 6
	RLIMIT_NOFILE     = 7
	RLIMIT_MEMLOCK    = 8
	RLIMIT_AS         = 9
	RLIMIT_LOCKS      = 10
	RLIMIT_SIGPENDING = 11
	RLIMIT_MSGQUEUE   = 12
	RLIMIT_NICE       = 13
	RLIMIT_RTPRIO     = 14
	RLIMIT_RTTIME     = 15
)

// RLimit corresponds to Linux's struct rlimit.
type RLimit struct {
	// Cur specifies the soft limit.
	Cur uint64
	// Max specifies the hard limit.
	Max uint64
}

const (
	// RLimInfinity is RLIM_INFINITY on Linux.
	RLimInfinity = ^uint64(0)

	// DefaultStackSoftLimit is called _STK_LIM in Linux.
	DefaultStackSoftLimit = 8 * 1024 * 1024

	// DefaultNprocLimit is defined in kernel/fork.c:set_max_threads, and
	// called MAX_THREADS / 2 in Linux.
	DefaultNprocLimit = FUTEX_TID_MASK / 2

	// DefaultNofileSoftLimit is called INR_OPEN_CUR in Linux.
	DefaultNofileSoftLimit = 1024

	// DefaultNofileHardLimit is called INR_OPEN_MAX in Linux.
	DefaultNofileHardLimit = 4096

	// DefaultMemlockLimit is called MLOCK_LIMIT in Linux.
	DefaultMemlockLimit = 64 * 1024

	// DefaultMsgqueueLimit is called MQ_BYTES_MAX in Linux.
	DefaultMsgqueueLimit = 819200
)

// InitRLimits is a map of initial rlimits set by Linux in
// include/asm-generic/resource.h.
var InitRLimits = map[int]RLimit{
	RLIMIT_CPU:        {RLimInfinity, RLimInfinity},
	RLIMIT_FSIZE:      {RLimInfinity, RLimInfinity},
	RLIMIT_DATA:       {RLimInfinity, RLimInfinity},
	RLIMIT_STACK:      {DefaultStackSoftLimit, RLimInfinity},
	RLIMIT_CORE:       {0, RLimInfinity},
	RLIMIT_RSS:        {RLimInfinity, RLimInfinity},
	RLIMIT_NPROC:      {DefaultNprocLimit, DefaultNprocLimit},
	RLIMIT_NOFILE:     {DefaultNofileSoftLimit, DefaultNofileHardLimit},
	RLIMIT_MEMLOCK:    {DefaultMemlockLimit, DefaultMemlockLimit},
	RLIMIT_AS:         {RLimInfinity, RLimInfinity},
	RLIMIT_LOCKS:      {RLimInfinity, RLimInfinity},
	RLIMIT_SIGPENDING: {0, 0},
	RLIMIT_MSGQUEUE:   {DefaultMsgqueueLimit, DefaultMsgqueueLimit},
	RLIMIT_NICE:       {0, 0},
	RLIMIT_RTPRIO:     {0, 0},
	RLIMIT_RTTIME:     {RLimInfinity, RLimInfinity},
}
