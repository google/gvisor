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

package kernel

import "math/bits"

// containerCPUAccounting is saved with the Kernel. Its mutex lives on Kernel.
// +stateify savable
type containerCPUAccounting struct {
	lifetime         map[string]uint64
	retiredGuest     uint64
	guestPrev        map[string]uint64
	cgroupPrev       map[string]uint64
	retiredPrev      uint64
	allocated        map[string]uint64
	retiredAllocated uint64
	overhead         uint64
	hostPrev         uint64
	hostSeen         bool
	epochReset       bool `state:"nosave"`
	source           string
}

func remapContainerCPUValues(values map[string]uint64, names, ids map[string]string) map[string]uint64 {
	if len(values) == 0 {
		return values
	}
	remapped := make(map[string]uint64, len(values))
	for oldID, value := range values {
		newID := oldID
		if name, ok := names[oldID]; ok {
			if id, ok := ids[name]; ok {
				newID = id
			}
		}
		remapped[newID] += value
	}
	return remapped
}

// ContainerCPUUsage returns task CPU charged to each container, including
// tasks whose thread groups have exited but whose container still exists.
func (k *Kernel) ContainerCPUUsage() map[string]uint64 {
	k.containerCPUMu.Lock()
	defer k.containerCPUMu.Unlock()
	usage := make(map[string]uint64, len(k.containerCPU.lifetime))
	for id, value := range k.containerCPU.lifetime {
		usage[id] = value
	}
	return usage
}

// ContainerCPUUsageWithFallback fills unreadable cgroups with their last
// successful sample, or task lifetime usage before the first cgroup sample.
// guest contains only successful cgroup reads; missing contains unreadable IDs.
func (k *Kernel) ContainerCPUUsageWithFallback(guest map[string]uint64, missing []string) map[string]uint64 {
	k.containerCPUMu.Lock()
	defer k.containerCPUMu.Unlock()
	a := &k.containerCPU
	if a.cgroupPrev == nil {
		a.cgroupPrev = make(map[string]uint64)
	}
	for id, value := range guest {
		if _, seen := a.cgroupPrev[id]; !seen {
			if _, hadBaseline := a.guestPrev[id]; hadBaseline {
				// The first cgroup sample cannot be compared with sentry CPU.
				a.guestPrev[id] = value
			}
		}
		a.cgroupPrev[id] = value
	}
	for _, id := range missing {
		if value, ok := a.cgroupPrev[id]; ok {
			guest[id] = value
		} else if value, ok := a.lifetime[id]; ok {
			guest[id] = value
		}
	}
	return guest
}

// RetireContainerCPU keeps destroyed containers' history out of live peers'
// host CPU allocation while bounding per-container state to live containers.
func (k *Kernel) RetireContainerCPU(id string) {
	k.containerCPUMu.Lock()
	defer k.containerCPUMu.Unlock()
	a := &k.containerCPU
	guest := a.lifetime[id]
	if a.guestPrev[id] > guest {
		guest = a.guestPrev[id]
	}
	if a.cgroupPrev[id] > guest {
		guest = a.cgroupPrev[id]
	}
	a.retiredGuest += guest
	a.retiredPrev += a.guestPrev[id]
	a.retiredAllocated += a.allocated[id]
	delete(a.lifetime, id)
	delete(a.guestPrev, id)
	delete(a.cgroupPrev, id)
	delete(a.allocated, id)
}

// AccountContainerCPU apportions only new host CPU using new guest CPU when
// the sandbox has a configured host cgroup. A failed host read freezes that
// mode's totals; explicitly hostless sandboxes use guest lifetime deltas.
func (k *Kernel) AccountContainerCPU(guest map[string]uint64, source string, host uint64, hostValid, hostConfigured bool) map[string]uint64 {
	k.containerCPUMu.Lock()
	defer k.containerCPUMu.Unlock()
	a := &k.containerCPU
	if a.allocated == nil {
		a.allocated = make(map[string]uint64)
	}
	if !hostConfigured {
		if a.epochReset {
			// Restore starts a new observation epoch, but the guest clock
			// may have kept running before the first Event. The source and
			// decreasing-value checks below decide whether it needs rebasing.
			a.hostSeen = false
			a.epochReset = false
		}
		if a.source != "" && (source != a.source || a.guestDecreased(guest)) {
			// The new guest source cannot be compared with the old one.
			a.source = source
			a.setGuestBaseline(guest)
			return a.currentAllocations(guest)
		}
		for id, value := range guest {
			if value > a.guestPrev[id] {
				a.allocated[id] += value - a.guestPrev[id]
			}
		}
		a.source = source
		a.setGuestBaseline(guest)
		return a.currentAllocations(guest)
	}
	if !hostValid {
		// Never expose guest CPU while a configured host clock is unreadable:
		// the next valid sample still includes that same host interval.
		return a.currentAllocations(guest)
	}

	if !a.hostSeen {
		if a.epochReset {
			// A restored sandbox starts a new host observation epoch;
			// preserve old charges and keep the first host value as overhead.
			a.overhead += host
		} else {
			a.distribute(host, guest, true)
		}
		a.hostSeen = true
		a.epochReset = false
		a.hostPrev = host
		a.source = source
		a.setGuestBaseline(guest)
		return a.currentAllocations(guest)
	}
	if host < a.hostPrev {
		// Concurrent callers can deliver an older host snapshot later.
		return a.currentAllocations(guest)
	}
	delta := host - a.hostPrev
	a.hostPrev = host
	if source != a.source || a.guestDecreased(guest) {
		// Guest accounting changed basis; charge the unmatched host window
		// to overhead rather than moving it to another container.
		a.overhead += delta
		a.source = source
		a.setGuestBaseline(guest)
		return a.currentAllocations(guest)
	}
	if delta == 0 {
		// A guest observation can lead its host observation. Keep the
		// guest baseline until there is host CPU to distribute.
		return a.currentAllocations(guest)
	}
	a.distribute(delta, guest, false)
	a.setGuestBaseline(guest)
	return a.currentAllocations(guest)
}

func (a *containerCPUAccounting) currentAllocations(guest map[string]uint64) map[string]uint64 {
	result := make(map[string]uint64, len(a.allocated)+len(guest))
	for id, value := range a.allocated {
		result[id] = value
	}
	for id := range guest {
		if _, ok := result[id]; !ok {
			result[id] = 0
		}
	}
	return result
}

func (a *containerCPUAccounting) setGuestBaseline(guest map[string]uint64) {
	a.guestPrev = make(map[string]uint64, len(guest))
	for id, value := range guest {
		a.guestPrev[id] = value
	}
	a.retiredPrev = a.retiredGuest
}

func (a *containerCPUAccounting) guestDecreased(guest map[string]uint64) bool {
	for id, value := range guest {
		if value < a.guestPrev[id] {
			return true
		}
	}
	return a.retiredGuest < a.retiredPrev
}

func (a *containerCPUAccounting) distribute(hostDelta uint64, guest map[string]uint64, initial bool) {
	var total uint64
	for id, value := range guest {
		if initial {
			total += value
		} else if value > a.guestPrev[id] {
			total += value - a.guestPrev[id]
		}
	}
	retiredDelta := a.retiredGuest - a.retiredPrev
	if initial {
		retiredDelta = a.retiredGuest
	}
	total += retiredDelta
	if total == 0 {
		a.overhead += hostDelta
		return
	}
	remaining := hostDelta
	for id, value := range guest {
		guestDelta := value
		if !initial {
			guestDelta -= a.guestPrev[id]
		}
		if guestDelta == 0 {
			continue
		}
		hi, lo := bits.Mul64(hostDelta, guestDelta)
		share, _ := bits.Div64(hi, lo, total)
		a.allocated[id] += share
		remaining -= share
	}
	if retiredDelta != 0 {
		hi, lo := bits.Mul64(hostDelta, retiredDelta)
		share, _ := bits.Div64(hi, lo, total)
		a.retiredAllocated += share
		remaining -= share
	}
	a.overhead += remaining
}
