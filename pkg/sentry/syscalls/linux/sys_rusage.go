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

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	ktime "gvisor.dev/gvisor/pkg/sentry/kernel/time"
	"gvisor.dev/gvisor/pkg/sentry/usage"
)

func getrusage(t *kernel.Task, which int32) linux.Rusage {
	var cs usage.CPUStats

	switch which {
	case linux.RUSAGE_SELF:
		cs = t.ThreadGroup().CPUStats()

	case linux.RUSAGE_CHILDREN:
		cs = t.ThreadGroup().JoinedChildCPUStats()

	case linux.RUSAGE_THREAD:
		cs = t.CPUStats()

	case linux.RUSAGE_BOTH:
		tg := t.ThreadGroup()
		cs = tg.CPUStats()
		cs.Accumulate(tg.JoinedChildCPUStats())
	}

	return linux.Rusage{
		UTime:  linux.NsecToTimeval(cs.UserTime.Nanoseconds()),
		STime:  linux.NsecToTimeval(cs.SysTime.Nanoseconds()),
		NVCSw:  int64(cs.VoluntarySwitches),
		MaxRSS: int64(t.MaxRSS(which) / 1024),
	}
}

// Getrusage implements linux syscall getrusage(2).
//	marked "y" are supported now
//	marked "*" are not used on Linux
//	marked "p" are pending for support
//
//	y    struct timeval ru_utime; /* user CPU time used */
//	y    struct timeval ru_stime; /* system CPU time used */
//	p    long   ru_maxrss;        /* maximum resident set size */
//	*    long   ru_ixrss;         /* integral shared memory size */
//	*    long   ru_idrss;         /* integral unshared data size */
//	*    long   ru_isrss;         /* integral unshared stack size */
//	p    long   ru_minflt;        /* page reclaims (soft page faults) */
//	p    long   ru_majflt;        /* page faults (hard page faults) */
//	*    long   ru_nswap;         /* swaps */
//	p    long   ru_inblock;       /* block input operations */
//	p    long   ru_oublock;       /* block output operations */
//	*    long   ru_msgsnd;        /* IPC messages sent */
//	*    long   ru_msgrcv;        /* IPC messages received */
//	*    long   ru_nsignals;      /* signals received */
//	y    long   ru_nvcsw;         /* voluntary context switches */
//	y    long   ru_nivcsw;        /* involuntary context switches */
func Getrusage(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	which := args[0].Int()
	addr := args[1].Pointer()

	if which != linux.RUSAGE_SELF && which != linux.RUSAGE_CHILDREN && which != linux.RUSAGE_THREAD {
		return 0, nil, linuxerr.EINVAL
	}

	ru := getrusage(t, which)
	_, err := ru.CopyOut(t, addr)
	return 0, nil, err
}

// Times implements linux syscall times(2).
func Times(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	addr := args[0].Pointer()

	// Calculate the ticks first, and figure out if any additional work is
	// necessary. Linux allows for a NULL addr, in which case only the
	// return value is meaningful. We don't need to do anything else.
	ticks := uintptr(ktime.NowFromContext(t).Nanoseconds() / linux.ClockTick.Nanoseconds())
	if addr == 0 {
		return ticks, nil, nil
	}

	cs1 := t.ThreadGroup().CPUStats()
	cs2 := t.ThreadGroup().JoinedChildCPUStats()
	r := linux.Tms{
		UTime:  linux.ClockTFromDuration(cs1.UserTime),
		STime:  linux.ClockTFromDuration(cs1.SysTime),
		CUTime: linux.ClockTFromDuration(cs2.UserTime),
		CSTime: linux.ClockTFromDuration(cs2.SysTime),
	}
	if _, err := r.CopyOut(t, addr); err != nil {
		return 0, nil, err
	}

	return ticks, nil, nil
}
