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

package sandbox

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	controlserver "gvisor.dev/gvisor/pkg/control/server"
	"gvisor.dev/gvisor/pkg/prometheus"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/runsc/boot"
)

// containerManager supplies distinct savings pairs to concurrent exports.
// Its name matches the control RPC receiver in the sandbox process.
type containerManager struct {
	entered chan<- struct{}
	release <-chan struct{}

	// lateZero delays a zero-valued first reply until another export completes.
	lateZero <-chan struct{}

	// +checkatomic
	requests atomic.Int64
}

func (cm *containerManager) GetSavings(_ *struct{}, savings *boot.Savings) error {
	n := time.Duration(cm.requests.Add(1))
	cm.entered <- struct{}{}
	if n == 1 && cm.lateZero != nil {
		// Model a snapshot taken before restoration completes.
		<-cm.lateZero
		return nil
	}
	<-cm.release
	savings.CPUTimeSaved = n * time.Second
	savings.WallTimeSaved = n * time.Minute
	return nil
}

// Metrics supplies an empty snapshot through the metrics control RPC.
type Metrics struct{}

func (*Metrics) Export(_ *control.MetricsExportOpts, data *control.MetricsExportData) error {
	data.Snapshot = prometheus.NewSnapshot()
	return nil
}

func TestConcurrentExportSavings(t *testing.T) {
	for _, tc := range []struct {
		name        string
		delayedZero bool
	}{
		{name: "simultaneous"},
		{name: "delayed-zero", delayedZero: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socketPath := filepath.Join(t.TempDir(), "control.sock")
			server, err := controlserver.Create(socketPath)
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			lateZero := make(chan struct{})
			unblockZero := sync.OnceFunc(func() { close(lateZero) })
			var wg sync.WaitGroup
			t.Cleanup(func() {
				// Stop does not cancel an RPC blocked inside its handler.
				unblock()
				unblockZero()
				wg.Wait()
				server.Stop(0)
			})
			cm := &containerManager{entered: entered, release: release}
			if tc.delayedZero {
				cm.lateZero = lateZero
			}
			server.Register(cm)
			server.Register(&Metrics{})
			if err := server.StartServing(); err != nil {
				t.Fatal(err)
			}
			s := &Sandbox{Restored: true, ControlSocketPath: socketPath}
			exportDone := make(chan struct{}, 2)
			for range 2 {
				wg.Go(func() {
					if _, err := s.ExportMetrics(control.MetricsExportOpts{}); err != nil {
						t.Errorf("ExportMetrics: %v", err)
					}
					exportDone <- struct{}{}
				})
			}
			// The RPCs use real socket I/O, so synctest cannot establish durable
			// blocking here. Channels order the test; this timeout only bounds failure.
			watchdog := time.After(5 * time.Second)
			for range 2 {
				select {
				case <-entered:
				case <-watchdog:
					t.Fatal("concurrent exports did not reach GetSavings")
				}
			}
			cached := make(chan [2]time.Duration, 1)
			wg.Go(func() {
				cpu, wall := s.TimeSaved()
				cached <- [2]time.Duration{cpu, wall}
			})
			select {
			case got := <-cached:
				if got != [2]time.Duration{} {
					t.Fatalf("TimeSaved before RPC completion = %v, want zero pair", got)
				}
			case <-watchdog:
				t.Fatal("TimeSaved blocked behind the savings RPCs")
			}
			unblock()
			if tc.delayedZero {
				// Cache the nonzero response before the older zero reply arrives.
				select {
				case <-exportDone:
				case <-watchdog:
					t.Fatal("nonzero savings export did not complete")
				}
				unblockZero()
			}
			wg.Wait()
			cpu, wall := s.TimeSaved()
			got := [2]time.Duration{cpu, wall}
			if tc.delayedZero {
				if want := [2]time.Duration{2 * time.Second, 2 * time.Minute}; got != want {
					t.Errorf("TimeSaved = %v, want cached nonzero pair %v", got, want)
				}
			} else if got != [2]time.Duration{time.Second, time.Minute} && got != [2]time.Duration{2 * time.Second, 2 * time.Minute} {
				t.Errorf("TimeSaved = %v, want one complete RPC response", got)
			}
		})
	}
}
