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
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
)

// SignalHandlers holds information about signal actions.
//
// +stateify savable
type SignalHandlers struct {
	// mu protects actions, as well as the signal state of all tasks and thread
	// groups using this SignalHandlers object. (See comment on
	// ThreadGroup.signalHandlers.)
	mu sync.Mutex `state:"nosave"`

	// actions is the action to be taken upon receiving each signal.
	actions map[linux.Signal]arch.SignalAct
}

// NewSignalHandlers returns a new SignalHandlers specifying all default
// actions.
func NewSignalHandlers() *SignalHandlers {
	return &SignalHandlers{
		actions: make(map[linux.Signal]arch.SignalAct),
	}
}

// Fork returns a copy of sh for a new thread group.
func (sh *SignalHandlers) Fork() *SignalHandlers {
	sh2 := NewSignalHandlers()
	sh.mu.Lock()
	defer sh.mu.Unlock()
	for sig, act := range sh.actions {
		sh2.actions[sig] = act
	}
	return sh2
}

// CopyForExec returns a copy of sh for a thread group that is undergoing an
// execve. (See comments in Task.finishExec.)
func (sh *SignalHandlers) CopyForExec() *SignalHandlers {
	sh2 := NewSignalHandlers()
	sh.mu.Lock()
	defer sh.mu.Unlock()
	for sig, act := range sh.actions {
		if act.Handler == arch.SignalActIgnore {
			sh2.actions[sig] = arch.SignalAct{
				Handler: arch.SignalActIgnore,
			}
		}
	}
	return sh2
}

// IsIgnored returns true if the signal is ignored.
func (sh *SignalHandlers) IsIgnored(sig linux.Signal) bool {
	sh.mu.Lock()
	defer sh.mu.Unlock()
	sa, ok := sh.actions[sig]
	return ok && sa.Handler == arch.SignalActIgnore
}

// dequeueActionLocked returns the SignalAct that should be used to handle sig.
//
// Preconditions: sh.mu must be locked.
func (sh *SignalHandlers) dequeueAction(sig linux.Signal) arch.SignalAct {
	act := sh.actions[sig]
	if act.IsResetHandler() {
		delete(sh.actions, sig)
	}
	return act
}
