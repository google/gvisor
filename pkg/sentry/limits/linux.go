// Copyright 2018 Google Inc.
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

package limits

import (
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
)

// FromLinuxResource maps linux resources to sentry LimitTypes.
var FromLinuxResource = map[int]LimitType{
	linux.RLIMIT_CPU:        CPU,
	linux.RLIMIT_FSIZE:      FileSize,
	linux.RLIMIT_DATA:       Data,
	linux.RLIMIT_STACK:      Stack,
	linux.RLIMIT_CORE:       Core,
	linux.RLIMIT_RSS:        Rss,
	linux.RLIMIT_NPROC:      ProcessCount,
	linux.RLIMIT_NOFILE:     NumberOfFiles,
	linux.RLIMIT_MEMLOCK:    MemoryPagesLocked,
	linux.RLIMIT_AS:         AS,
	linux.RLIMIT_LOCKS:      Locks,
	linux.RLIMIT_SIGPENDING: SignalsPending,
	linux.RLIMIT_MSGQUEUE:   MessageQueueBytes,
	linux.RLIMIT_NICE:       Nice,
	linux.RLIMIT_RTPRIO:     RealTimePriority,
	linux.RLIMIT_RTTIME:     Rttime,
}

// FromLinux maps linux rlimit values to sentry Limits, being careful to handle
// infinities.
func FromLinux(rl uint64) uint64 {
	if rl == linux.RLimInfinity {
		return Infinity
	}
	return rl
}

// ToLinux maps sentry Limits to linux rlimit values, being careful to handle
// infinities.
func ToLinux(l uint64) uint64 {
	if l == Infinity {
		return linux.RLimInfinity
	}
	return l
}

// NewLinuxLimitSet returns a LimitSet whose values match the default rlimits
// in Linux.
func NewLinuxLimitSet() (*LimitSet, error) {
	ls := NewLimitSet()
	for rlt, rl := range linux.InitRLimits {
		lt, ok := FromLinuxResource[rlt]
		if !ok {
			return nil, fmt.Errorf("unknown rlimit type %v", rlt)
		}
		ls.SetUnchecked(lt, Limit{
			Cur: FromLinux(rl.Cur),
			Max: FromLinux(rl.Max),
		})
	}
	return ls, nil
}

// NewLinuxDistroLimitSet returns a new LimitSet whose values are typical
// for a booted Linux distro.
//
// Many Linux init systems adjust the default Linux limits to values more
// expected by the rest of the userspace. NewLinuxDistroLimitSet returns a
// LimitSet with sensible defaults for applications that aren't starting
// their own init system.
func NewLinuxDistroLimitSet() (*LimitSet, error) {
	ls, err := NewLinuxLimitSet()
	if err != nil {
		return nil, err
	}

	// Adjust ProcessCount to a lower value because GNU bash allocates 16
	// bytes per proc and OOMs if this number is set too high. Value was
	// picked arbitrarily.
	//
	// 1,048,576 ought to be enough for anyone.
	l := ls.Get(ProcessCount)
	l.Cur = 1 << 20
	ls.Set(ProcessCount, l)
	return ls, nil
}
