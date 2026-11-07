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

package sandboxsetup

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/log"
)

func TestShouldExposeNvidiaDevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "nvidiactl", path: "/dev/nvidiactl", want: true},
		{name: "nvidia-uvm", path: "/dev/nvidia-uvm", want: true},
		{name: "nvidia0", path: "/dev/nvidia0", want: true},
		{name: "nvidia1", path: "/dev/nvidia1", want: true},
		{name: "nvidia42", path: "/dev/nvidia42", want: true},
		{name: "nvidia-uvm-tools", path: "/dev/nvidia-uvm-tools", want: true},
		{name: "nvidia-modeset", path: "/dev/nvidia-modeset", want: false},
		{name: "not nvidia", path: "/dev/sda", want: false},
		{name: "nvidia prefix but not device", path: "/dev/nvidia-cap1", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeNvidiaDevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeNvidiaDevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

// warningRecorder is a log.Emitter that records warning messages.
type warningRecorder struct {
	warnings []string
}

// Emit implements log.Emitter.Emit.
func (w *warningRecorder) Emit(_ int, level log.Level, _ time.Time, format string, v ...any) {
	if level == log.Warning {
		w.warnings = append(w.warnings, fmt.Sprintf(format, v...))
	}
}

func TestShouldExposeVFIODevice(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		want        bool
		wantWarning bool
	}{
		{name: "vfio dir", path: "/dev/vfio/vfio", want: true},
		{name: "vfio group", path: "/dev/vfio/0", want: true},
		{name: "vfio dir itself", path: "/dev/vfio", want: true},
		{name: "not vfio", path: "/dev/sda", want: false},
		{name: "not vfio and not clean", path: "/dev/sda/", want: false},
		{name: "vfio prefix but not dir", path: "/dev/vfiox", want: false},
		{name: "dotdot escape", path: "/dev/vfio/../../etc/shadow", want: false, wantWarning: true},
		{name: "dotdot within dir", path: "/dev/vfio/../vfio/0", want: false, wantWarning: true},
		{name: "trailing slash", path: "/dev/vfio/0/", want: false, wantWarning: true},
		{name: "double slash", path: "/dev/vfio//0", want: false, wantWarning: true},
		{name: "empty", path: "", want: false},
	}
	oldTarget := log.Log().Emitter
	defer log.SetTarget(oldTarget)
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			rec := &warningRecorder{}
			log.SetTarget(rec)
			got := ShouldExposeVFIODevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeVFIODevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
			gotWarning := len(rec.warnings) > 0 && strings.Contains(rec.warnings[0], tst.path)
			if gotWarning != tst.wantWarning || len(rec.warnings) > 1 {
				t.Errorf("ShouldExposeVFIODevice(%q) logged warnings %q, want warning naming the path: %v", tst.path, rec.warnings, tst.wantWarning)
			}
		})
	}
}

func TestShouldExposeTpuDevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// VFIO devices are always detected as TPU devices regardless of sysfs.
		{name: "vfio device", path: "/dev/vfio/0", want: true},
		{name: "vfio vfio", path: "/dev/vfio/vfio", want: true},
		{name: "not tpu", path: "/dev/sda", want: false},
		{name: "vfio dotdot escape", path: "/dev/vfio/../../etc/shadow", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeTpuDevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeTpuDevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

func TestShouldExposeRDMADevice(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		want        bool
		wantWarning bool
	}{
		{name: "uverbs0", path: "/dev/infiniband/uverbs0", want: true},
		{name: "uverbs12", path: "/dev/infiniband/uverbs12", want: true},
		{name: "rdma_cm", path: "/dev/infiniband/rdma_cm", want: false},
		{name: "uverbs without number", path: "/dev/infiniband/uverbs", want: false},
		{name: "uverbs non-numeric suffix", path: "/dev/infiniband/uverbs0x", want: false},
		{name: "uverbs subpath", path: "/dev/infiniband/uverbs0/foo", want: false},
		{name: "not anchored", path: "/tmp/dev/infiniband/uverbs0", want: false},
		{name: "dotdot escape", path: "/dev/infiniband/uverbs0/../../../etc/shadow", want: false, wantWarning: true},
		{name: "dotdot to uverbs", path: "/dev/infiniband/../infiniband/uverbs0", want: false, wantWarning: true},
		{name: "trailing slash", path: "/dev/infiniband/uverbs0/", want: false, wantWarning: true},
		{name: "double slash", path: "/dev/infiniband//uverbs0", want: false, wantWarning: true},
		{name: "not rdma", path: "/dev/sda", want: false},
		{name: "not rdma and not clean", path: "/dev/sda/", want: false},
		{name: "empty", path: "", want: false},
	}
	oldTarget := log.Log().Emitter
	defer log.SetTarget(oldTarget)
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			rec := &warningRecorder{}
			log.SetTarget(rec)
			got := ShouldExposeRDMADevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeRDMADevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
			gotWarning := len(rec.warnings) > 0 && strings.Contains(rec.warnings[0], tst.path)
			if gotWarning != tst.wantWarning || len(rec.warnings) > 1 {
				t.Errorf("ShouldExposeRDMADevice(%q) logged warnings %q, want warning naming the path: %v", tst.path, rec.warnings, tst.wantWarning)
			}
		})
	}
}
