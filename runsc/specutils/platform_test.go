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

package specutils

import (
	"errors"
	"slices"
	"testing"

	"gvisor.dev/gvisor/runsc/config"
)

// fakeProbe returns a probeFunc that accepts only the given platforms.
func fakeProbe(available ...string) probeFunc {
	return func(p autoPlatform) error {
		if slices.Contains(available, p.name) {
			return nil
		}
		return errors.New("unavailable")
	}
}

func TestChoosePlatform(t *testing.T) {
	all := []string{"kvm", "systrap"}
	for _, tc := range []struct {
		name       string
		env        hostEnv
		available  []string
		want       string
		wantDevice string
	}{
		{name: "bare metal prefers kvm", available: all, want: "kvm", wantDevice: "/dev/kvm"},
		{name: "no kvm device uses systrap", available: []string{"systrap"}, want: "systrap"},
		{name: "vm skips kvm", env: hostEnv{inVM: true}, available: all, want: "systrap"},
		{name: "gpu skips kvm", env: hostEnv{hasGPU: true}, available: all, want: "systrap"},
		{name: "nothing available", available: nil, want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, device, skipped := choosePlatform(tc.env, fakeProbe(tc.available...))
			if got != tc.want || device != tc.wantDevice {
				t.Errorf("choosePlatform(%v) = %q, %q (skipped: %q), want %q, %q", tc.env, got, device, skipped, tc.want, tc.wantDevice)
			}
		})
	}
}

func TestChoosePlatformReportsSkipped(t *testing.T) {
	env := hostEnv{inVM: true}
	got, _, skipped := choosePlatform(env, fakeProbe())
	if got != "" {
		t.Fatalf("choosePlatform(%v) = %q, want none", env, got)
	}
	for _, want := range []string{
		"kvm: inside a VM",
		"systrap: unavailable",
	} {
		if !slices.Contains(skipped, want) {
			t.Errorf("choosePlatform(%v) skipped = %q, want it to contain %q", env, skipped, want)
		}
	}
}

func TestHypervisorFlagSet(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cpuinfo string
		want    bool
	}{
		{name: "x86 vm", cpuinfo: "processor\t: 0\nflags\t\t: fpu vme hypervisor lahf_lm\n", want: true},
		{name: "x86 bare metal", cpuinfo: "processor\t: 0\nflags\t\t: fpu vme lahf_lm\nvmx flags\t: vnmi\n", want: false},
		{name: "arm64", cpuinfo: "processor\t: 0\nFeatures\t: fp asimd evtstrm\n", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hypervisorFlagSet(tc.cpuinfo); got != tc.want {
				t.Errorf("hypervisorFlagSet(%q) = %t, want %t", tc.cpuinfo, got, tc.want)
			}
		})
	}
}

// smbiosStruct returns an SMBIOS structure of type typ with a formatted area
// of size bytes, followed by strs.
func smbiosStruct(typ byte, size int, strs ...string) []byte {
	b := make([]byte, size)
	b[0], b[1] = typ, byte(size)
	for _, s := range strs {
		b = append(append(b, s...), 0)
	}
	if len(strs) == 0 {
		b = append(b, 0)
	}
	return append(b, 0)
}

// biosInfo returns a BIOS Information structure whose BIOS characteristics
// extension byte 2 is ext2.
func biosInfo(ext2 byte) []byte {
	b := smbiosStruct(0, 0x18, "vendor", "version")
	b[0x13] = ext2
	return b
}

func TestSMBIOSVMBitSet(t *testing.T) {
	for _, tc := range []struct {
		name  string
		table []byte
		want  bool
	}{
		{name: "vm bit set", table: biosInfo(0x1c), want: true},
		{name: "vm bit unset", table: biosInfo(0x0c), want: false},
		{name: "bios info after system info", table: append(smbiosStruct(1, 0x1b, "maker"), biosInfo(0x10)...), want: true},
		{name: "no extension byte 2", table: smbiosStruct(0, 0x13), want: false},
		{name: "truncated", table: biosInfo(0x10)[:0x10], want: false},
		{name: "empty", table: nil, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := smbiosVMBitSet(tc.table); got != tc.want {
				t.Errorf("smbiosVMBitSet(%x) = %t, want %t", tc.table, got, tc.want)
			}
		})
	}
}

func TestResolvePlatformKeepsExplicitPlatform(t *testing.T) {
	conf := &config.Config{Platform: "ptrace"}
	if err := ResolvePlatform(conf, nil); err != nil {
		t.Fatalf("ResolvePlatform() failed: %v", err)
	}
	if conf.Platform != "ptrace" {
		t.Errorf("ResolvePlatform() changed platform to %q, want %q", conf.Platform, "ptrace")
	}
}

func TestResolvePlatformRejectsDevicePath(t *testing.T) {
	conf := &config.Config{Platform: config.PlatformAuto, PlatformDevicePath: "/dev/kvm"}
	if err := ResolvePlatform(conf, nil); err == nil {
		t.Errorf("ResolvePlatform() succeeded with --platform_device_path, want error")
	}
}
