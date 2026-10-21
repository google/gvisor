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

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"
	"unsafe"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/runsc/flag"
)

//go:linkname vdsoClockgettimeSym runtime.vdsoClockgettimeSym
var vdsoClockgettimeSym uintptr

func callVDSOClockGettime(fn uintptr, clockid int32, ts uintptr) int32
func rdtsc() uint64

type vdsoClock struct {
	file  string
	count int
}

func (*vdsoClock) Name() string {
	return "vdso-clock"
}

func (*vdsoClock) Synopsis() string {
	return "checks VDSO clock_gettime vs syscall clock_gettime across checkpoint/restore"
}

func (*vdsoClock) Usage() string {
	return "vdso-clock --file=<output file> [--count=<iterations>]\n"
}

func (v *vdsoClock) SetFlags(f *flag.FlagSet) {
	f.StringVar(&v.file, "file", "", "output file path")
	f.IntVar(&v.count, "count", 0, "number of iterations before exiting (0 for infinite)")
}

func (v *vdsoClock) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if v.file == "" {
		log.Fatalf("--file is required")
	}

	outFile, err := os.OpenFile(v.file, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("failed to open output file %q: %v", v.file, err)
	}
	defer outFile.Close()

	if vdsoClockgettimeSym == 0 {
		log.Fatalf("vdsoClockgettimeSym is nil")
	}

	iter := 0
	var prevVdsoNs, prevSysNs int64
	var prevTSC uint64
	for {
		iter++
		var tsVDSO, tsSys unix.Timespec
		ret := callVDSOClockGettime(vdsoClockgettimeSym, unix.CLOCK_MONOTONIC, uintptr(unsafe.Pointer(&tsVDSO)))
		if ret != 0 {
			log.Fatalf("VDSO clock_gettime failed: %d", ret)
		}
		if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &tsSys); err != nil {
			log.Fatalf("Syscall clock_gettime failed: %v", err)
		}
		curTSC := rdtsc()

		vdsoNs := tsVDSO.Nano()
		sysNs := tsSys.Nano()
		diff := vdsoNs - sysNs
		absDiff := diff
		if absDiff < 0 {
			absDiff = -absDiff
		}

		if prevVdsoNs != 0 && vdsoNs < prevVdsoNs {
			msg := fmt.Sprintf("FAIL: VDSO monotonic time went backwards: prev=%d current=%d delta=%d\n", prevVdsoNs, vdsoNs, vdsoNs-prevVdsoNs)
			fmt.Print(msg)
			outFile.WriteString(msg)
			outFile.Sync()
			return subcommands.ExitFailure
		}
		if prevSysNs != 0 && sysNs < prevSysNs {
			msg := fmt.Sprintf("FAIL: syscall monotonic time went backwards: prev=%d current=%d delta=%d\n", prevSysNs, sysNs, sysNs-prevSysNs)
			fmt.Print(msg)
			outFile.WriteString(msg)
			outFile.Sync()
			return subcommands.ExitFailure
		}
		if prevTSC != 0 && curTSC < prevTSC {
			msg := fmt.Sprintf("FAIL: RDTSC went backwards: prev=%d current=%d delta=%d\n", prevTSC, curTSC, int64(curTSC)-int64(prevTSC))
			fmt.Print(msg)
			outFile.WriteString(msg)
			outFile.Sync()
			return subcommands.ExitFailure
		}
		prevVdsoNs = vdsoNs
		prevSysNs = sysNs
		prevTSC = curTSC

		// If diff exceeds 1 second, report desynchronization and exit.
		if absDiff > int64(time.Second) {
			msg := fmt.Sprintf("FAIL: VDSO desynchronized from syscall: vdso=%d sys=%d diff=%d\n", vdsoNs, sysNs, diff)
			fmt.Print(msg)
			outFile.WriteString(msg)
			outFile.Sync()
			return subcommands.ExitFailure
		}

		msg := fmt.Sprintf("OK: vdso=%d sys=%d diff=%d tsc=%d\n", vdsoNs, sysNs, diff, curTSC)
		outFile.WriteString(msg)
		outFile.Sync()

		if v.count > 0 && iter >= v.count {
			return subcommands.ExitSuccess
		}

		time.Sleep(50 * time.Millisecond)
	}
}
