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
	"os"
	"path/filepath"
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
			name:  "has path separators",
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

func TestTranslateUID(t *testing.T) {
	for _, tc := range []struct {
		name   string
		uid    int
		uidMap string
		want   int
	}{
		{
			name:   "initial user namespace",
			uid:    1000,
			uidMap: "         0          0 4294967295\n",
			want:   1000,
		},
		{
			// Rootless container runtimes map the unprivileged caller to UID 0, so
			// the UID visible to runsc says nothing about its privileges.
			name:   "caller mapped to root",
			uid:    0,
			uidMap: "         0       1000          1\n         1     100000      65536\n",
			want:   1000,
		},
		{
			name:   "offset within range",
			uid:    5,
			uidMap: "         0       1000          1\n         1     100000      65536\n",
			want:   100004,
		},
		{
			name:   "unmapped",
			uid:    99999,
			uidMap: "         0       1000          1\n",
			want:   99999,
		},
		{
			name:   "malformed",
			uid:    7,
			uidMap: "this is not a uid map\n",
			want:   7,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "uid_map")
			if err := os.WriteFile(path, []byte(tc.uidMap), 0644); err != nil {
				t.Fatalf("os.WriteFile(%q): %v", path, err)
			}
			if got := translateUID(tc.uid, path); got != tc.want {
				t.Errorf("translateUID(%d, %q) = %d, want %d", tc.uid, path, got, tc.want)
			}
		})
	}
}

func TestTranslateUIDMissingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist")
	if got := translateUID(1000, path); got != 1000 {
		t.Errorf("translateUID(1000, %q) = %d, want 1000", path, got)
	}
}

func TestUserBusAddress(t *testing.T) {
	t.Run("from environment", func(t *testing.T) {
		const want = "unix:path=/run/user/1000/bus"
		t.Setenv("DBUS_SESSION_BUS_ADDRESS", want)
		t.Setenv("XDG_RUNTIME_DIR", "")
		got, err := userBusAddress()
		if err != nil {
			t.Fatalf("userBusAddress() failed: %v", err)
		}
		if got != want {
			t.Errorf("userBusAddress() = %q, want %q", got, want)
		}
	})

	// Container runtimes do not always propagate DBUS_SESSION_BUS_ADDRESS, so the
	// well-known path under XDG_RUNTIME_DIR must also be found.
	t.Run("from XDG_RUNTIME_DIR", func(t *testing.T) {
		dir := t.TempDir()
		busPath := filepath.Join(dir, "bus")
		if err := os.WriteFile(busPath, nil, 0644); err != nil {
			t.Fatalf("os.WriteFile(%q): %v", busPath, err)
		}
		t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
		t.Setenv("XDG_RUNTIME_DIR", dir)
		got, err := userBusAddress()
		if err != nil {
			t.Fatalf("userBusAddress() failed: %v", err)
		}
		if want := "unix:path=" + dbus.EscapeBusAddressValue(busPath); got != want {
			t.Errorf("userBusAddress() = %q, want %q", got, want)
		}
	})

	t.Run("not found", func(t *testing.T) {
		t.Setenv("DBUS_SESSION_BUS_ADDRESS", "")
		t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
		if got, err := userBusAddress(); err == nil {
			t.Errorf("userBusAddress() = %q, want error", got)
		}
	})
}

func TestMakePath(t *testing.T) {
	for _, tc := range []struct {
		name string
		cg   cgroupSystemd
		want string
	}{
		{
			name: "system instance",
			cg: cgroupSystemd{
				Name:        "123",
				Parent:      "system.slice",
				ScopePrefix: "runsc",
				cgroupV2:    cgroupV2{Mountpoint: "/sys/fs/cgroup"},
			},
			want: "/sys/fs/cgroup/system.slice/runsc-123.scope",
		},
		{
			// Units managed by a per-user systemd instance are nested under that
			// instance's own cgroup.
			name: "user instance",
			cg: cgroupSystemd{
				Name:        "123",
				Parent:      "user.slice",
				ScopePrefix: "libpod",
				Rootless:    true,
				ManagerCG:   "/user.slice/user-1000.slice/user@1000.service",
				cgroupV2:    cgroupV2{Mountpoint: "/sys/fs/cgroup"},
			},
			want: "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/user.slice/libpod-123.scope",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cg.MakePath(""); got != tc.want {
				t.Errorf("MakePath() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestInstall(t *testing.T) {
	const dialErr = "dial unix /var/run/dbus/system_bus_socket: connect: no such file or directory"
	for _, tc := range []struct {
		name             string
		res              *specs.LinuxResources
		wantProps        []systemdDbus.Property
		updatedRes       *specs.LinuxResources
		wantUpdatedProps []systemdDbus.Property
		err              error
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
			updatedRes: &specs.LinuxResources{
				CPU: &specs.LinuxCPU{
					Shares: uint64Ptr(1),
					Period: uint64Ptr(10000),
					Quota:  int64Ptr(300000),
					Cpus:   "2",
					Mems:   "3",
				},
			},
			wantUpdatedProps: []systemdDbus.Property{
				// initial properties
				{"CPUWeight", dbus.MakeVariant(convertCPUSharesToCgroupV2Value(1))},
				{"CPUQuotaPeriodUSec", dbus.MakeVariant(uint64(20000))},
				{"CPUQuotaPerSecUSec", dbus.MakeVariant(uint64(15000000))},
				{"AllowedCPUs", dbus.MakeVariant([]byte{1 << 4})},
				{"AllowedMemoryNodes", dbus.MakeVariant([]byte{1 << 5})},
				// updated properties
				{"CPUWeight", dbus.MakeVariant(convertCPUSharesToCgroupV2Value(1))},
				{"CPUQuotaPeriodUSec", dbus.MakeVariant(uint64(10000))},
				{"CPUQuotaPerSecUSec", dbus.MakeVariant(uint64(30000000))},
				{"AllowedCPUs", dbus.MakeVariant([]byte{1 << 2})},
				{"AllowedMemoryNodes", dbus.MakeVariant([]byte{1 << 3})},
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
			// Rootless is set explicitly because the expected properties and the
			// dial error below describe the system instance.
			cg := cgroupSystemd{Name: "123", Parent: "parent.slice", Rootless: false}
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

			if tc.updatedRes != nil {
				if err := cg.Update(tc.updatedRes); err != nil && err.Error() != dialErr {
					if !errors.Is(err, tc.err) {
						t.Fatalf("Wrong error, got: %s, want: %s", err, tc.err)
					}
				}
				filteredProps = filterProperties(cg.properties, tc.wantUpdatedProps)
				if diff := cmp.Diff(filteredProps, tc.wantUpdatedProps, cmper, sorter); diff != "" {
					t.Errorf("cgroup properties list diff %s", diff)
				}
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
