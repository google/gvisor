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

package kernel

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
)

// +stateify savable
type savedPendingSignal struct {
	si    *arch.SignalInfo
	timer *IntervalTimer
}

// saveSignals is invoked by stateify.
func (p *pendingSignals) saveSignals() []savedPendingSignal {
	var pending []savedPendingSignal
	for _, q := range p.signals {
		for ps := q.pendingSignalList.Front(); ps != nil; ps = ps.Next() {
			pending = append(pending, savedPendingSignal{
				si:    ps.SignalInfo,
				timer: ps.timer,
			})
		}
	}
	return pending
}

// loadSignals is invoked by stateify.
func (p *pendingSignals) loadSignals(pending []savedPendingSignal) {
	for _, sps := range pending {
		p.enqueue(sps.si, sps.timer)
	}
}
