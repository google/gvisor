// Copyright 2019 The gVisor Authors.
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

package proc

import (
	"bytes"
	"fmt"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// cpuStats contains the breakdown of CPU time for /proc/stat.
type cpuStats struct {
	// user is time spent in userspace tasks with non-positive niceness.
	user uint64

	// nice is time spent in userspace tasks with positive niceness.
	nice uint64

	// system is time spent in non-interrupt kernel context.
	system uint64

	// idle is time spent idle.
	idle uint64

	// ioWait is time spent waiting for IO.
	ioWait uint64

	// irq is time spent in interrupt context.
	irq uint64

	// softirq is time spent in software interrupt context.
	softirq uint64

	// steal is involuntary wait time.
	steal uint64

	// guest is time spent in guests with non-positive niceness.
	guest uint64

	// guestNice is time spent in guests with positive niceness.
	guestNice uint64
}

// String implements fmt.Stringer.
func (c cpuStats) String() string {
	return fmt.Sprintf("%d %d %d %d %d %d %d %d %d %d", c.user, c.nice, c.system, c.idle, c.ioWait, c.irq, c.softirq, c.steal, c.guest, c.guestNice)
}

// statData implements vfs.DynamicBytesSource for /proc/stat.
//
// +stateify savable
type statData struct {
	// k is the owning Kernel.
	k *kernel.Kernel
}

var _ vfs.DynamicBytesSource = (*statData)(nil)

// Generate implements vfs.DynamicBytesSource.Generate.
func (s *statData) Generate(ctx context.Context, buf *bytes.Buffer) error {
	// TODO(b/37226836): We currently export only zero CPU stats. We could
	// at least provide some aggregate stats.
	var cpu cpuStats
	fmt.Fprintf(buf, "cpu  %s\n", cpu)

	for c, max := uint(0), s.k.ApplicationCores(); c < max; c++ {
		fmt.Fprintf(buf, "cpu%d %s\n", c, cpu)
	}

	// The total number of interrupts is dependent on the CPUs and PCI
	// devices on the system. See arch_probe_nr_irqs.
	//
	// Since we don't report real interrupt stats, just choose an arbitrary
	// value from a representative VM.
	const numInterrupts = 256

	// The Kernel doesn't handle real interrupts, so report all zeroes.
	// TODO(b/37226836): We could count page faults as #PF.
	fmt.Fprintf(buf, "intr 0") // total
	for i := 0; i < numInterrupts; i++ {
		fmt.Fprintf(buf, " 0")
	}
	fmt.Fprintf(buf, "\n")

	// Total number of context switches.
	// TODO(b/37226836): Count this.
	fmt.Fprintf(buf, "ctxt 0\n")

	// CLOCK_REALTIME timestamp from boot, in seconds.
	fmt.Fprintf(buf, "btime %d\n", s.k.Timekeeper().BootTime().Seconds())

	// Total number of clones.
	// TODO(b/37226836): Count this.
	fmt.Fprintf(buf, "processes 0\n")

	// Number of runnable tasks.
	// TODO(b/37226836): Count this.
	fmt.Fprintf(buf, "procs_running 0\n")

	// Number of tasks waiting on IO.
	// TODO(b/37226836): Count this.
	fmt.Fprintf(buf, "procs_blocked 0\n")

	// Number of each softirq handled.
	fmt.Fprintf(buf, "softirq 0") // total
	for i := 0; i < linux.NumSoftIRQ; i++ {
		fmt.Fprintf(buf, " 0")
	}
	fmt.Fprintf(buf, "\n")
	return nil
}
