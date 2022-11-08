// Copyright The runc Authors.
// Copyright The containerd Authors.
// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cgroup

import (
	"errors"
	"testing"

	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
	dbus "github.com/godbus/dbus/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

var (
	defaultProps         = []systemdDbus.Property{}
	mandatoryControllers = []string{"cpu", "cpuset", "io", "memory", "pids"}
)

func TestIsValidSlice(t *testing.T) {
	for _, tc := range []struct {
		name  string
		slice string
		err   error
	}{
		{
			name:  "success",
			slice: "system.slice",
		},
		{
			name:  "root slice",
			slice: "-.slice",
		},
		{
			name:  "path in slice",
			slice: "system-child-grandchild.slice",
		},
		{
			name:  "bad suffix",
			slice: "system.scope",
			err:   ErrInvalidSlice,
		},
		{
			name:  "has path seperators",
			slice: "systemd.slice/child.slice",
			err:   ErrInvalidSlice,
		},
		{
			name:  "invalid separator pattern",
			slice: "systemd--child.slice",
			err:   ErrInvalidSlice,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validSlice(tc.slice)
			if !errors.Is(err, tc.err) {
				t.Errorf("validSlice(%s) = %v, want %v", tc.slice, err, tc.err)
			}
		})
	}
}

func TestExpandSlice(t *testing.T) {
	original := "test-a-b.slice"
	want := "/test.slice/test-a.slice/test-a-b.slice"
	expanded := expandSlice(original)
	if expanded != want {
		t.Errorf("expandSlice(%q) = %q, want %q", original, expanded, want)
	}
}

func TestInstall(t *testing.T) {
	for _, tc := range []struct {
		name      string
		res       *specs.LinuxResources
		wantProps []systemdDbus.Property
		err       error
	}{
		{
			name: "defaults",
			res:  nil,
			wantProps: []systemdDbus.Property{
				{"Slice", dbus.MakeVariant("parent.slice")},
				{Name: "Description", Value: dbus.MakeVariant("Secure container 123")},
				{Name: "MemoryAccounting", Value: dbus.MakeVariant(true)},
				{Name: "CPUAccounting", Value: dbus.MakeVariant(true)},
				{Name: "TasksAccounting", Value: dbus.MakeVariant(true)},
				{Name: "IOAccounting", Value: dbus.MakeVariant(true)},
				{Name: "Delegate", Value: dbus.MakeVariant(true)},
				{Name: "DefaultDependencies", Value: dbus.MakeVariant(false)},
			},
		},
		{
			name: "memory",
			res: &specs.LinuxResources{
				Memory: &specs.LinuxMemory{
					Limit:       int64Ptr(1),
					Swap:        int64Ptr(2),
					Reservation: int64Ptr(3),
				},
			},
			wantProps: []systemdDbus.Property{
				{"MemoryMax", dbus.MakeVariant(uint64(1))},
				{"MemoryLow", dbus.MakeVariant(uint64(3))},
				{"MemorySwapMax", dbus.MakeVariant(uint64(1))},
			},
		},
		{
			name: "memory no limit",
			res: &specs.LinuxResources{
				Memory: &specs.LinuxMemory{
					Swap: int64Ptr(1),
				},
			},
			err: ErrBadResourceSpec,
		},
		{
			name: "cpu defaults",
			res: &specs.LinuxResources{
				CPU: &specs.LinuxCPU{
					Shares: uint64Ptr(0),
					Quota:  int64Ptr(5),
					Period: uint64Ptr(0),
				},
			},
			wantProps: []systemdDbus.Property{
				{"CPUQuotaPerSecUSec", dbus.MakeVariant(uint64(10000))},
			},
		},
		{
			name: "cpu",
			res: &specs.LinuxResources{
				CPU: &specs.LinuxCPU{
					Shares: uint64Ptr(1),
					Period: uint64Ptr(20000),
					Quota:  int64Ptr(300000),
					Cpus:   "4",
					Mems:   "5",
				},
			},
			wantProps: []systemdDbus.Property{
				{"CPUWeight", dbus.MakeVariant(convertCPUSharesToCgroupV2Value(1))},
				{"CPUQuotaPeriodUSec", dbus.MakeVariant(uint64(20000))},
				{"CPUQuotaPerSecUSec", dbus.MakeVariant(uint64(15000000))},
				{"AllowedCPUs", dbus.MakeVariant([]byte{1 << 4})},
				{"AllowedMemoryNodes", dbus.MakeVariant([]byte{1 << 5})},
			},
		},
		{
			name: "cpuset",
			res: &specs.LinuxResources{
				CPU: &specs.LinuxCPU{
					Cpus: "1-3,5",
					Mems: "5-8",
				},
			},
			wantProps: []systemdDbus.Property{
				{"AllowedCPUs", dbus.MakeVariant([]byte{0b_101110})},
				{"AllowedMemoryNodes", dbus.MakeVariant([]byte{1, 0b_11100000})},
			},
		},
		{
			name: "io",
			res: &specs.LinuxResources{
				BlockIO: &specs.LinuxBlockIO{
					Weight: uint16Ptr(1),
					WeightDevice: []specs.LinuxWeightDevice{
						makeLinuxWeightDevice(2, 3, uint16Ptr(4), uint16Ptr(0)),
						makeLinuxWeightDevice(5, 6, uint16Ptr(7), uint16Ptr(0)),
					},
					ThrottleReadBpsDevice: []specs.LinuxThrottleDevice{
						makeLinuxThrottleDevice(8, 9, 10),
						makeLinuxThrottleDevice(11, 12, 13),
					},
					ThrottleWriteBpsDevice: []specs.LinuxThrottleDevice{
						makeLinuxThrottleDevice(14, 15, 16),
					},
					ThrottleReadIOPSDevice: []specs.LinuxThrottleDevice{
						makeLinuxThrottleDevice(17, 18, 19),
					},
					ThrottleWriteIOPSDevice: []specs.LinuxThrottleDevice{
						makeLinuxThrottleDevice(20, 21, 22),
					},
				},
			},
			wantProps: []systemdDbus.Property{
				{"IOWeight", dbus.MakeVariant(convertBlkIOToIOWeightValue(1))},
				{"IODeviceWeight", dbus.MakeVariant("2:3 4")},
				{"IODeviceWeight", dbus.MakeVariant("5:6 7")},
				{"IOReadBandwidthMax", dbus.MakeVariant("8:9 10")},
				{"IOReadBandwidthMax", dbus.MakeVariant("11:12 13")},
				{"IOWriteBandwidthMax", dbus.MakeVariant("14:15 16")},
				{"IOReadIOPSMax", dbus.MakeVariant("17:18 19")},
				{"IOWriteIOPSMax", dbus.MakeVariant("20:21 22")},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cg := cgroupSystemd{Name: "123", Parent: "parent.slice"}
			cg.Controllers = mandatoryControllers
			err := cg.Install(tc.res)
			if !errors.Is(err, tc.err) {
				t.Fatalf("Wrong error, got: %s, want: %s", err, tc.err)
			}
			cmper := cmp.Comparer(func(a dbus.Variant, b dbus.Variant) bool {
				return a.String() == b.String()
			})
			sorter := cmpopts.SortSlices(func(a systemdDbus.Property, b systemdDbus.Property) bool {
				return (a.Name + a.Value.String()) > (b.Name + b.Value.String())
			})
			filteredProps := filterProperties(cg.properties, tc.wantProps)
			if diff := cmp.Diff(filteredProps, tc.wantProps, cmper, sorter); diff != "" {
				t.Errorf("cgroup properties list diff %s", diff)
			}
		})
	}
}

// filterProperties filters the list of properties in got to ones with
// the names of properties specified in want.
func filterProperties(got []systemdDbus.Property, want []systemdDbus.Property) []systemdDbus.Property {
	if want == nil {
		return nil
	}
	filterMap := map[string]any{}
	for _, prop := range want {
		filterMap[prop.Name] = nil
	}
	filtered := []systemdDbus.Property{}
	for _, prop := range got {
		if _, ok := filterMap[prop.Name]; ok {
			filtered = append(filtered, prop)
		}
	}
	return filtered
}
