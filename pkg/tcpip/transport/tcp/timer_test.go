// Copyright 2020 The gVisor Authors.
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

package tcp

import (
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/sleep"
	"gvisor.dev/gvisor/pkg/tcpip/faketime"
)

func TestCleanup(t *testing.T) {
	const (
		timerDurationSeconds     = 2
		isAssertedTimeoutSeconds = timerDurationSeconds + 1
	)

	clock := faketime.NewManualClock()

	tmr := timer{}
	w := sleep.Waker{}
	tmr.init(clock, w.Assert)
	tmr.enable(timerDurationSeconds * time.Second)
	tmr.cleanup()

	if want := (timer{}); tmr != want {
		t.Errorf("got tmr = %+v, want = %+v", tmr, want)
	}

	// The waker should not be asserted.
	for i := 0; i < isAssertedTimeoutSeconds; i++ {
		clock.Advance(time.Second)
		if w.IsAsserted() {
			t.Fatalf("waker asserted unexpectedly")
		}
	}
}
