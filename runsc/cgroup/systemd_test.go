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
	"path/filepath"
	"strconv"
	"testing"

	systemdDbus "github.com/coreos/go-systemd/v22/dbus"
	dbus "github.com/godbus/dbus/v5"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

var defaultProps = []systemdDbus.Property{}

func TestInstall(t *testing.T) {
	for _, tc := range []struct {
		name       string
		res        *specs.LinuxResources
		cgroupPath string
		wantProps  []systemdDbus.Property
		err        error
	}{
		{
			name:       "bad parent",
			res:        nil,
			cgroupPath: "not_a_slice",
			err:        ErrInvalidGroupPath,
		},
		{
			name: "no limits",
			res:  nil,
			wantProps: []systemdDbus.Property{
				{"Slice", dbus.MakeVariant("parent.slice")},
				{Name: "Description", Value: dbus.MakeVariant("runsc container ")},
				{Name: "MemoryAccounting", Value: dbus.MakeVariant(true)},
				{Name: "CPUAccounting", Value: dbus.MakeVariant(true)},
				{Name: "TasksAccounting", Value: dbus.MakeVariant(true)},
				{Name: "IOAccounting", Value: dbus.MakeVariant(true)},
				{Name: "Delegate", Value: dbus.MakeVariant(true)},
			},
			cgroupPath: "parent.slice",
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
			cgroupPath: "parent.slice",
			wantProps: []systemdDbus.Property{
				{"MemoryMax", dbus.MakeVariant(int64(1))},
				{"MemoryLow", dbus.MakeVariant(int64(3))},
				{"MemorySwapMax", dbus.MakeVariant("1")},
			},
		},
		{
			name: "memory no limit",
			res: &specs.LinuxResources{
				Memory: &specs.LinuxMemory{
					Swap: int64Ptr(1),
				},
			},
			err:        ErrBadResourceSpec,
			cgroupPath: "parent.slice",
		},
		{
			name: "cpu defaults",
			res: &specs.LinuxResources{
				CPU: &specs.LinuxCPU{
					Shares: uint64Ptr(0),
					Quota:  int64Ptr(0),
					Period: uint64Ptr(0),
				},
			},
			cgroupPath: "parent.slice",
			wantProps: []systemdDbus.Property{
				{"CPUQuotaPeriodSec", dbus.MakeVariant(strconv.FormatUint(defaultPeriod/10, 10) + "ms")},
			},
		},
		{
			name: "cpu",
			res: &specs.LinuxResources{
				CPU: &specs.LinuxCPU{
					Shares: uint64Ptr(1),
					Period: uint64Ptr(20),
					Quota:  int64Ptr(3),
					Cpus:   "4",
					Mems:   "5",
				},
			},
			cgroupPath: "parent.slice",
			wantProps: []systemdDbus.Property{
				{"CPUShares", dbus.MakeVariant(convertCPUSharesToCgroupV2Value(1))},
				{"CPUQuotaPeriodSec", dbus.MakeVariant("2ms")},
				{"CPUQuota", dbus.MakeVariant("3%")},
				{"AllowedCPUs", dbus.MakeVariant("4")},
				{"AllowedMemoryNodes", dbus.MakeVariant("5")},
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
			cgroupPath: "parent.slice",
			wantProps: []systemdDbus.Property{
				{"IOWeight", dbus.MakeVariant(uint16(1))},
				{"IODevice", dbus.MakeVariant("2:3 4")},
				{"IODevice", dbus.MakeVariant("5:6 7")},
				{"IOReadBandwidth", dbus.MakeVariant("8:9 10")},
				{"IOReadBandwidth", dbus.MakeVariant("11:12 13")},
				{"IOWriteBandwidth", dbus.MakeVariant("14:15 16")},
				{"IOReadIOPS", dbus.MakeVariant("17:18 19")},
				{"IOWriteIOPS", dbus.MakeVariant("20:21 22")},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := testutil.TmpDir()
			testPath := filepath.Join(dir, tc.cgroupPath)

			cg := cgroupSystemd{
				Path: testPath,
			}
			err := cg.Install(tc.res)
			if !errors.Is(err, tc.err) {
				t.Fatalf("Wrong error, got: %s, want: %s", tc.err, err)
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
	filterMap := map[string]interface{}{}
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
