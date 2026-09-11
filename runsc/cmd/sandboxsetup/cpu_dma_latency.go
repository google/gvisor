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

package sandboxsetup

import (
	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/marshal/primitive"
)

const (
	cpuDMALatencyPath = "/dev/cpu_dma_latency"

	// cpuDMALatencyUsec bounds the exit latency of host CPU idle states
	// while /dev/cpu_dma_latency is held open. 10us permits shallow states
	// (C1/C1E, ~1-4us exit latency) but forbids deep ones (C6, ~170-210us
	// on the CPUs matched by slowDeepIdleCPU()). 10us was picked
	// semi-arbitrarily: as of writing, 10us-15us was the deepest wake latency
	// observed on CPUs NOT matched by slowDeepIdleCPU() and some GPU machines
	// already ship with this setting. It must not be 0, which would forbid
	// even C1 and make idle CPUs spin in a polling loop.
	cpuDMALatencyUsec = 10
)

// MaybeCapCPUIdleStates limits how deep host CPUs may idle if the host CPU
// takes a long time to exit its deepest idle state. Platforms that report
// Requirements.FrequentHostThreadWakeups wake sleeping host threads at a
// very high rate; each wake-up that lands on a deeply idling CPU pays the
// full exit latency, which is invisible to CPU profilers because the waking
// CPU isn't executing.
//
// On success, returns an FD for /dev/cpu_dma_latency. The kernel enforces
// the constraint only while a reference to the open file exists, and drops
// it when the last reference is released (including on process death). Returns
// -1 if the host CPU is not affected or on failure; this is best effort.
func MaybeCapCPUIdleStates() int {
	if !slowDeepIdleCPU() {
		return -1
	}
	fd, err := unix.Open(cpuDMALatencyPath, unix.O_WRONLY, 0)
	if err != nil {
		log.Infof("Not capping host CPU idle states: open(%s): %v", cpuDMALatencyPath, err)
		return -1
	}
	// The kernel expects a raw native-endian integer, not ASCII.
	usec := primitive.Uint32(cpuDMALatencyUsec)
	var buf [4]byte
	usec.MarshalUnsafe(buf[:])
	if _, err := unix.Write(fd, buf[:]); err != nil {
		log.Infof("Not capping host CPU idle states: write(%s): %v", cpuDMALatencyPath, err)
		unix.Close(fd)
		return -1
	}
	log.Infof("Capped host CPU idle state exit latency to %dus", cpuDMALatencyUsec)
	return fd
}
