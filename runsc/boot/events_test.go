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

package boot

import (
	"runtime"
	"testing"
	"time"

	"gvisor.dev/gvisor/runsc/boot/sentryapi"
)

func TestEventReleasesSaveMuWhileWaitingForContainer(t *testing.T) {
	for _, cpuOnly := range []bool{false, true} {
		name := "initial PID check"
		if cpuOnly {
			name = "CPU snapshot"
		}
		t.Run(name, func(t *testing.T) {
			l := &Loader{}
			l.mu.Lock()
			cm := &containerManager{l: l}
			started := make(chan struct{})
			eventDone := make(chan error, 1)
			go func() {
				close(started)
				var out sentryapi.EventOut
				if cpuOnly {
					eventDone <- cm.cpuStats(&sentryapi.EventArgs{CID: "removed"}, &out)
				} else {
					eventDone <- cm.Event(&sentryapi.EventArgs{CID: "removed"}, &out)
				}
			}()
			<-started
			runtime.Gosched()

			checkpointDone := make(chan struct{})
			go func() {
				for i := 0; i < 32; {
					l.saveMu.Lock()
					i++
					l.saveMu.Unlock()
					runtime.Gosched()
				}
				close(checkpointDone)
			}()
			select {
			case <-checkpointDone:
			case <-time.After(2 * time.Second):
				t.Error("saveMu remained held while Event waited for the container lifecycle lock")
			}
			l.mu.Unlock()
			select {
			case err := <-eventDone:
				if err == nil {
					t.Error("Event succeeded for a removed container")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("Event did not finish after releasing the container lock")
			}
			<-checkpointDone
		})
	}
}

func TestEventCPURejectsRetiredContainer(t *testing.T) {
	l, cleanup, err := createLoader(testConfig(), testSpec())
	if err != nil {
		t.Fatalf("creating loader: %v", err)
	}
	defer cleanup()
	defer l.Destroy()
	defer l.ctrl.srv.Stop(time.Second)
	const cid = "foo"
	if _, err := l.pidsCount(cid); err != nil {
		t.Fatalf("initial Event existence check: %v", err)
	}
	l.k.AccountContainerCPU(map[string]uint64{cid: 100}, "sentry", 0, false, false)
	l.mu.Lock()
	l.k.RetireContainerCPU(cid)
	delete(l.processes, execID{cid: cid})
	l.mu.Unlock()
	cm := &containerManager{l: l}
	var out sentryapi.EventOut
	if err := cm.cpuStats(&sentryapi.EventArgs{CID: cid}, &out); err == nil {
		t.Fatalf("CPU snapshot succeeded after retirement, total=%d", out.Event.Data.CPU.Usage.Total)
	}
}
