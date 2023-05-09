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
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
)

// TTY defines the relationship between a thread group and its controlling
// terminal.
//
// +stateify savable
type TTY struct {
	// Index is the terminal index. It is immutable.
	Index uint32

	mu sync.Mutex `state:"nosave"`

	// tg is protected by mu.
	tg *ThreadGroup
}

// TTY returns the thread group's controlling terminal. If nil, there is no
// controlling terminal.
func (tg *ThreadGroup) TTY() *TTY {
	tg.pidns.owner.mu.RLock()
	defer tg.pidns.owner.mu.RUnlock()
	tg.signalHandlers.mu.Lock()
	defer tg.signalHandlers.mu.Unlock()
	return tg.tty
}

// SignalForegroundProcessGroup sends the signal to the foreground process
// group of the TTY.
func (tty *TTY) SignalForegroundProcessGroup(info *linux.SignalInfo) {
	tty.mu.Lock()
	defer tty.mu.Unlock()

	tg := tty.tg
	if tg == nil {
		// This TTY is not a controlling thread group. This can happen
		// if it was opened with O_NOCTTY, or if it failed the checks
		// on session and leaders in SetControllingTTY(). There is
		// nothing to signal.
		return
	}

	tg.pidns.owner.mu.Lock()
	tg.signalHandlers.mu.Lock()
	fg := tg.processGroup.session.foreground
	tg.signalHandlers.mu.Unlock()
	tg.pidns.owner.mu.Unlock()

	if fg == nil {
		// Nothing to signal.
		return
	}

	// SendSignal will take TaskSet.mu and signalHandlers.mu, so we cannot
	// hold them here.
	if err := fg.SendSignal(info); err != nil {
		log.Warningf("failed to signal foreground process group (pgid=%d): %v", fg.id, err)
	}
}
