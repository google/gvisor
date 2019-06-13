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
	"gvisor.dev/gvisor/pkg/sentry/time"
)

// beforeSave is invoked by stateify.
func (t *Timekeeper) beforeSave() {
	if t.stop != nil {
		panic("pauseUpdates must be called before Save")
	}

	// N.B. we want the *offset* monotonic time.
	var err error
	if t.saveMonotonic, err = t.GetTime(time.Monotonic); err != nil {
		panic("unable to get current monotonic time: " + err.Error())
	}

	if t.saveRealtime, err = t.GetTime(time.Realtime); err != nil {
		panic("unable to get current realtime: " + err.Error())
	}
}

// afterLoad is invoked by stateify.
func (t *Timekeeper) afterLoad() {
	t.restored = make(chan struct{})
}
