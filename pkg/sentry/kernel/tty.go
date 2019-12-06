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

import "sync"

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
	tg.signalHandlers.mu.Lock()
	defer tg.signalHandlers.mu.Unlock()
	return tg.tty
}
