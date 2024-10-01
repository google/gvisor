// Copyright 2024 The gVisor Authors.
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
	"sync/atomic"
	"unsafe"
)

// SignalHandlers returns the signal handlers used by tg. The returned value
// may be racy; see the field comment for ThreadGroup.signalHandlers.
func (tg *ThreadGroup) SignalHandlers() *SignalHandlers {
	return (*SignalHandlers)(atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&tg.signalHandlers))))
}

// Preconditions: The only permitted caller of this function is
// Task.finishExec(), as described in the field comment for
// ThreadGroup.signalHandlers.
func (tg *ThreadGroup) setSignalHandlersLocked(sh *SignalHandlers) {
	atomic.StorePointer((*unsafe.Pointer)(unsafe.Pointer(&tg.signalHandlers)), unsafe.Pointer(sh))
}
