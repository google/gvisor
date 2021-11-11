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

package cgroup

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

var debianMountinfo = `
35 24 0:30 / /sys/fs/cgroup ro shared:9 - tmpfs tmpfs ro
36 35 0:31 / /sys/fs/cgroup/unified rw shared:10 - cgroup2 cgroup2 rw
37 35 0:32 / /sys/fs/cgroup/systemd rw - cgroup cgroup rw,name=systemd
41 35 0:36 / /sys/fs/cgroup/cpu,cpuacct rw shared:16 - cgroup cgroup rw,cpu,cpuacct
42 35 0:37 / /sys/fs/cgroup/freezer rw shared:17 - cgroup cgroup rw,freezer
43 35 0:38 / /sys/fs/cgroup/hugetlb rw shared:18 - cgroup cgroup rw,hugetlb
44 35 0:39 / /sys/fs/cgroup/cpuset rw shared:19 - cgroup cgroup rw,cpuset
45 35 0:40 / /sys/fs/cgroup/net_cls,net_prio rw shared:20 - cgroup cgroup rw,net_cls,net_prio
46 35 0:41 / /sys/fs/cgroup/pids rw shared:21 - cgroup cgroup rw,pids
47 35 0:42 / /sys/fs/cgroup/perf_event rw shared:22 - cgroup cgroup rw,perf_event
48 35 0:43 / /sys/fs/cgroup/memory rw shared:23 - cgroup cgroup rw,memory
49 35 0:44 / /sys/fs/cgroup/blkio rw shared:24 - cgroup cgroup rw,blkio
50 35 0:45 / /sys/fs/cgroup/devices rw shared:25 - cgroup cgroup rw,devices
51 35 0:46 / /sys/fs/cgroup/rdma rw shared:26 - cgroup cgroup rw,rdma
`

var dindMountinfo = `
05 04 0:64 / /sys/fs/cgroup rw - tmpfs tmpfs rw,mode=755
06 05 0:32 /docker/136 /sys/fs/cgroup/systemd ro master:11 - cgroup cgroup rw,xattr,name=systemd
07 05 0:36 /docker/136 /sys/fs/cgroup/cpu,cpuacct ro master:16 - cgroup cgroup rw,cpu,cpuacct
08 05 0:37 /docker/136 /sys/fs/cgroup/freezer ro master:17 - cgroup cgroup rw,freezer
09 05 0:38 /docker/136 /sys/fs/cgroup/hugetlb ro master:18 - cgroup cgroup rw,hugetlb
10 05 0:39 /docker/136 /sys/fs/cgroup/cpuset ro master:19 - cgroup cgroup rw,cpuset
11 05 0:40 /docker/136 /sys/fs/cgroup/net_cls,net_prio ro master:20 - cgroup cgroup rw,net_cls,net_prio
12 05 0:41 /docker/136 /sys/fs/cgroup/pids ro master:21 - cgroup cgroup rw,pids
13 05 0:42 /docker/136 /sys/fs/cgroup/perf_event ro master:22 - cgroup cgroup rw,perf_event
14 05 0:43 /docker/136 /sys/fs/cgroup/memory ro master:23 - cgroup cgroup rw,memory
16 05 0:44 /docker/136 /sys/fs/cgroup/blkio ro master:24 - cgroup cgroup rw,blkio
17 05 0:45 /docker/136 /sys/fs/cgroup/devices ro master:25 - cgroup cgroup rw,devices
18 05 0:46 / /sys/fs/cgroup/rdma ro master:26 - cgroup cgroup rw,rdma
`

func TestUninstallEnoent(t *testing.T) {
	c := cgroupV1{
		// Use a non-existent name.
		Name: "runsc-test-uninstall-656e6f656e740a",
		Own:  make(map[string]bool),
	}
	for key := range controllers {
		c.Own[key] = true
	}
	if err := c.Uninstall(); err != nil {
		t.Errorf("Uninstall() failed: %v", err)
	}
}

func TestCountCpuset(t *testing.T) {
	for _, tc := range []struct {
		str   string
		want  int
		error bool
	}{
		{str: "0", want: 1},
		{str: "0,1,2,8,9,10", want: 6},
		{str: "0-1", want: 2},
		{str: "0-7", want: 8},
		{str: "0-7,16,32-39,64,65", want: 19},
		{str: "a", error: true},
		{str: "5-a", error: true},
		{str: "a-5", error: true},
		{str: "-10", error: true},
		{str: "15-", error: true},
		{str: "-", error: true},
		{str: "--", error: true},
	} {
		t.Run(tc.str, func(t *testing.T) {
			got, err := countCpuset(tc.str)
			if tc.error {
				if err == nil {
					t.Errorf("countCpuset(%q) should have failed", tc.str)
				}
			} else {
				if err != nil {
					t.Errorf("countCpuset(%q) failed: %v", tc.str, err)
				}
				if tc.want != got {
					t.Errorf("countCpuset(%q) want: %d, got: %d", tc.str, tc.want, got)
				}
			}
		})
	}
}

func uint16Ptr(v uint16) *uint16 {
	return &v
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func int64Ptr(v int64) *int64 {
	return &v
}

func uint64Ptr(v uint64) *uint64 {
	return &v
}

func boolPtr(v bool) *bool {
	return &v
}

func createDir(dir string, contents map[string]string) error {
	for name := range contents {
		path := filepath.Join(dir, name)
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		f.Close()
	}
	return nil
}

func checkDir(t *testing.T, dir string, contents map[string]string) {
	all, err := ioutil.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	fileCount := 0
	for _, file := range all {
		if file.IsDir() {
			// Only want to compare files.
			continue
		}
		fileCount++

		want, ok := contents[file.Name()]
		if !ok {
			t.Errorf("file not expected: %q", file.Name())
			continue
		}
		gotBytes, err := ioutil.ReadFile(filepath.Join(dir, file.Name()))
		if err != nil {
			t.Fatal(err.Error())
		}
		got := strings.TrimSuffix(string(gotBytes), "\n")
		if got != want {
			t.Errorf("wrong file content, file: %q, want: %q, got: %q", file.Name(), want, got)
		}
	}
	if fileCount != len(contents) {
		t.Errorf("file is missing, want: %v, got: %v", contents, all)
	}
}

func makeLinuxWeightDevice(major, minor int64, weight, leafWeight *uint16) specs.LinuxWeightDevice {
	rv := specs.LinuxWeightDevice{
		Weight:     weight,
		LeafWeight: leafWeight,
	}
	rv.Major = major
	rv.Minor = minor
	return rv
}

func makeLinuxThrottleDevice(major, minor int64, rate uint64) specs.LinuxThrottleDevice {
	rv := specs.LinuxThrottleDevice{
		Rate: rate,
	}
	rv.Major = major
	rv.Minor = minor
	return rv
}

func TestBlockIO(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spec  *specs.LinuxBlockIO
		wants map[string]string
	}{
		{
			name: "simple",
			spec: &specs.LinuxBlockIO{
				Weight:     uint16Ptr(1),
				LeafWeight: uint16Ptr(2),
			},
			wants: map[string]string{
				"blkio.weight":      "1",
				"blkio.leaf_weight": "2",
			},
		},
		{
			name: "weight_device",
			spec: &specs.LinuxBlockIO{
				WeightDevice: []specs.LinuxWeightDevice{
					makeLinuxWeightDevice(1, 2, uint16Ptr(3), uint16Ptr(4)),
				},
			},
			wants: map[string]string{
				"blkio.weight_device":      "1:2 3",
				"blkio.leaf_weight_device": "1:2 4",
			},
		},
		{
			name: "weight_device_nil_values",
			spec: &specs.LinuxBlockIO{
				WeightDevice: []specs.LinuxWeightDevice{
					makeLinuxWeightDevice(1, 2, nil, nil),
				},
			},
		},
		{
			name: "throttle",
			spec: &specs.LinuxBlockIO{
				ThrottleReadBpsDevice: []specs.LinuxThrottleDevice{
					makeLinuxThrottleDevice(1, 2, 3),
				},
				ThrottleReadIOPSDevice: []specs.LinuxThrottleDevice{
					makeLinuxThrottleDevice(4, 5, 6),
				},
				ThrottleWriteBpsDevice: []specs.LinuxThrottleDevice{
					makeLinuxThrottleDevice(7, 8, 9),
				},
				ThrottleWriteIOPSDevice: []specs.LinuxThrottleDevice{
					makeLinuxThrottleDevice(10, 11, 12),
				},
			},
			wants: map[string]string{
				"blkio.throttle.read_bps_device":   "1:2 3",
				"blkio.throttle.read_iops_device":  "4:5 6",
				"blkio.throttle.write_bps_device":  "7:8 9",
				"blkio.throttle.write_iops_device": "10:11 12",
			},
		},
		{
			name: "nil_values",
			spec: &specs.LinuxBlockIO{},
		},
		{
			name: "nil",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := ioutil.TempDir(testutil.TmpDir(), "cgroup")
			if err != nil {
				t.Fatalf("error creating temporary directory: %v", err)
			}
			defer os.RemoveAll(dir)
			if err := createDir(dir, tc.wants); err != nil {
				t.Fatalf("createDir(): %v", err)
			}

			spec := &specs.LinuxResources{
				BlockIO: tc.spec,
			}
			ctrlr := blockIO{}
			if err := ctrlr.set(spec, dir); err != nil {
				t.Fatalf("ctrlr.set(): %v", err)
			}
			checkDir(t, dir, tc.wants)
		})
	}
}

func TestCPU(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spec  *specs.LinuxCPU
		wants map[string]string
	}{
		{
			name: "all",
			spec: &specs.LinuxCPU{
				Shares:          uint64Ptr(1),
				Quota:           int64Ptr(2),
				Period:          uint64Ptr(3),
				RealtimeRuntime: int64Ptr(4),
				RealtimePeriod:  uint64Ptr(5),
			},
			wants: map[string]string{
				"cpu.shares":        "1",
				"cpu.cfs_quota_us":  "2",
				"cpu.cfs_period_us": "3",
				"cpu.rt_runtime_us": "4",
				"cpu.rt_period_us":  "5",
			},
		},
		{
			name: "nil_values",
			spec: &specs.LinuxCPU{},
		},
		{
			name: "nil",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := ioutil.TempDir(testutil.TmpDir(), "cgroup")
			if err != nil {
				t.Fatalf("error creating temporary directory: %v", err)
			}
			defer os.RemoveAll(dir)
			if err := createDir(dir, tc.wants); err != nil {
				t.Fatalf("createDir(): %v", err)
			}

			spec := &specs.LinuxResources{
				CPU: tc.spec,
			}
			ctrlr := cpu{}
			if err := ctrlr.set(spec, dir); err != nil {
				t.Fatalf("ctrlr.set(): %v", err)
			}
			checkDir(t, dir, tc.wants)
		})
	}
}

func TestCPUSet(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spec  *specs.LinuxCPU
		wants map[string]string
	}{
		{
			name: "all",
			spec: &specs.LinuxCPU{
				Cpus: "foo",
				Mems: "bar",
			},
			wants: map[string]string{
				"cpuset.cpus": "foo",
				"cpuset.mems": "bar",
			},
		},
		// Don't test nil values because they are copied from the parent.
		// See TestCPUSetAncestor().
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := ioutil.TempDir(testutil.TmpDir(), "cgroup")
			if err != nil {
				t.Fatalf("error creating temporary directory: %v", err)
			}
			defer os.RemoveAll(dir)
			if err := createDir(dir, tc.wants); err != nil {
				t.Fatalf("createDir(): %v", err)
			}

			spec := &specs.LinuxResources{
				CPU: tc.spec,
			}
			ctrlr := cpuSet{}
			if err := ctrlr.set(spec, dir); err != nil {
				t.Fatalf("ctrlr.set(): %v", err)
			}
			checkDir(t, dir, tc.wants)
		})
	}
}

// TestCPUSetAncestor checks that, when not available, value is read from
// parent directory.
func TestCPUSetAncestor(t *testing.T) {
	// Prepare master directory with cgroup files that will be propagated to
	// children.
	grandpa, err := ioutil.TempDir(testutil.TmpDir(), "cgroup")
	if err != nil {
		t.Fatalf("error creating temporary directory: %v", err)
	}
	defer os.RemoveAll(grandpa)

	if err := ioutil.WriteFile(filepath.Join(grandpa, "cpuset.cpus"), []byte("parent-cpus"), 0666); err != nil {
		t.Fatalf("ioutil.WriteFile(): %v", err)
	}
	if err := ioutil.WriteFile(filepath.Join(grandpa, "cpuset.mems"), []byte("parent-mems"), 0666); err != nil {
		t.Fatalf("ioutil.WriteFile(): %v", err)
	}

	for _, tc := range []struct {
		name string
		spec *specs.LinuxCPU
	}{
		{
			name: "nil_values",
			spec: &specs.LinuxCPU{},
		},
		{
			name: "nil",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Create empty files in intermediate directory. They should be ignored
			// when reading, and then populated from parent.
			parent, err := ioutil.TempDir(grandpa, "parent")
			if err != nil {
				t.Fatalf("error creating temporary directory: %v", err)
			}
			defer os.RemoveAll(parent)
			if _, err := os.Create(filepath.Join(parent, "cpuset.cpus")); err != nil {
				t.Fatalf("os.Create(): %v", err)
			}
			if _, err := os.Create(filepath.Join(parent, "cpuset.mems")); err != nil {
				t.Fatalf("os.Create(): %v", err)
			}

			// cgroup files mmust exist.
			dir, err := ioutil.TempDir(parent, "child")
			if err != nil {
				t.Fatalf("error creating temporary directory: %v", err)
			}
			if _, err := os.Create(filepath.Join(dir, "cpuset.cpus")); err != nil {
				t.Fatalf("os.Create(): %v", err)
			}
			if _, err := os.Create(filepath.Join(dir, "cpuset.mems")); err != nil {
				t.Fatalf("os.Create(): %v", err)
			}

			spec := &specs.LinuxResources{
				CPU: tc.spec,
			}
			ctrlr := cpuSet{}
			if err := ctrlr.set(spec, dir); err != nil {
				t.Fatalf("ctrlr.set(): %v", err)
			}
			want := map[string]string{
				"cpuset.cpus": "parent-cpus",
				"cpuset.mems": "parent-mems",
			}
			// Both path and dir must have been populated from grandpa.
			checkDir(t, parent, want)
			checkDir(t, dir, want)
		})
	}
}

func TestHugeTlb(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spec  []specs.LinuxHugepageLimit
		wants map[string]string
	}{
		{
			name: "single",
			spec: []specs.LinuxHugepageLimit{
				{
					Pagesize: "1G",
					Limit:    123,
				},
			},
			wants: map[string]string{
				"hugetlb.1G.limit_in_bytes": "123",
			},
		},
		{
			name: "multiple",
			spec: []specs.LinuxHugepageLimit{
				{
					Pagesize: "1G",
					Limit:    123,
				},
				{
					Pagesize: "2G",
					Limit:    456,
				},
				{
					Pagesize: "1P",
					Limit:    789,
				},
			},
			wants: map[string]string{
				"hugetlb.1G.limit_in_bytes": "123",
				"hugetlb.2G.limit_in_bytes": "456",
				"hugetlb.1P.limit_in_bytes": "789",
			},
		},
		{
			name: "nil",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := ioutil.TempDir(testutil.TmpDir(), "cgroup")
			if err != nil {
				t.Fatalf("error creating temporary directory: %v", err)
			}
			defer os.RemoveAll(dir)
			if err := createDir(dir, tc.wants); err != nil {
				t.Fatalf("createDir(): %v", err)
			}

			spec := &specs.LinuxResources{
				HugepageLimits: tc.spec,
			}
			ctrlr := hugeTLB{}
			if err := ctrlr.set(spec, dir); err != nil {
				t.Fatalf("ctrlr.set(): %v", err)
			}
			checkDir(t, dir, tc.wants)
		})
	}
}

func TestMemory(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spec  *specs.LinuxMemory
		wants map[string]string
	}{
		{
			name: "all",
			spec: &specs.LinuxMemory{
				Limit:            int64Ptr(1),
				Reservation:      int64Ptr(2),
				Swap:             int64Ptr(3),
				Kernel:           int64Ptr(4),
				KernelTCP:        int64Ptr(5),
				Swappiness:       uint64Ptr(6),
				DisableOOMKiller: boolPtr(true),
			},
			wants: map[string]string{
				"memory.limit_in_bytes":          "1",
				"memory.soft_limit_in_bytes":     "2",
				"memory.memsw.limit_in_bytes":    "3",
				"memory.kmem.limit_in_bytes":     "4",
				"memory.kmem.tcp.limit_in_bytes": "5",
				"memory.swappiness":              "6",
				"memory.oom_control":             "1",
			},
		},
		{
			// Disable OOM killer should only write when set to true.
			name: "oomkiller",
			spec: &specs.LinuxMemory{
				DisableOOMKiller: boolPtr(false),
			},
		},
		{
			name: "nil_values",
			spec: &specs.LinuxMemory{},
		},
		{
			name: "nil",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := ioutil.TempDir(testutil.TmpDir(), "cgroup")
			if err != nil {
				t.Fatalf("error creating temporary directory: %v", err)
			}
			defer os.RemoveAll(dir)
			if err := createDir(dir, tc.wants); err != nil {
				t.Fatalf("createDir(): %v", err)
			}

			spec := &specs.LinuxResources{
				Memory: tc.spec,
			}
			ctrlr := memory{}
			if err := ctrlr.set(spec, dir); err != nil {
				t.Fatalf("ctrlr.set(): %v", err)
			}
			checkDir(t, dir, tc.wants)
		})
	}
}

func TestNetworkClass(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spec  *specs.LinuxNetwork
		wants map[string]string
	}{
		{
			name: "all",
			spec: &specs.LinuxNetwork{
				ClassID: uint32Ptr(1),
			},
			wants: map[string]string{
				"net_cls.classid": "1",
			},
		},
		{
			name: "nil_values",
			spec: &specs.LinuxNetwork{},
		},
		{
			name: "nil",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := ioutil.TempDir(testutil.TmpDir(), "cgroup")
			if err != nil {
				t.Fatalf("error creating temporary directory: %v", err)
			}
			defer os.RemoveAll(dir)
			if err := createDir(dir, tc.wants); err != nil {
				t.Fatalf("createDir(): %v", err)
			}

			spec := &specs.LinuxResources{
				Network: tc.spec,
			}
			ctrlr := networkClass{}
			if err := ctrlr.set(spec, dir); err != nil {
				t.Fatalf("ctrlr.set(): %v", err)
			}
			checkDir(t, dir, tc.wants)
		})
	}
}

func TestNetworkPriority(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spec  *specs.LinuxNetwork
		wants map[string]string
	}{
		{
			name: "all",
			spec: &specs.LinuxNetwork{
				Priorities: []specs.LinuxInterfacePriority{
					{
						Name:     "foo",
						Priority: 1,
					},
				},
			},
			wants: map[string]string{
				"net_prio.ifpriomap": "foo 1",
			},
		},
		{
			name: "nil_values",
			spec: &specs.LinuxNetwork{},
		},
		{
			name: "nil",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := ioutil.TempDir(testutil.TmpDir(), "cgroup")
			if err != nil {
				t.Fatalf("error creating temporary directory: %v", err)
			}
			defer os.RemoveAll(dir)
			if err := createDir(dir, tc.wants); err != nil {
				t.Fatalf("createDir(): %v", err)
			}

			spec := &specs.LinuxResources{
				Network: tc.spec,
			}
			ctrlr := networkPrio{}
			if err := ctrlr.set(spec, dir); err != nil {
				t.Fatalf("ctrlr.set(): %v", err)
			}
			checkDir(t, dir, tc.wants)
		})
	}
}

func TestPids(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spec  *specs.LinuxPids
		wants map[string]string
	}{
		{
			name: "all",
			spec: &specs.LinuxPids{Limit: 1},
			wants: map[string]string{
				"pids.max": "1",
			},
		},
		{
			name: "nil_values",
			spec: &specs.LinuxPids{},
		},
		{
			name: "nil",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, err := ioutil.TempDir(testutil.TmpDir(), "cgroup")
			if err != nil {
				t.Fatalf("error creating temporary directory: %v", err)
			}
			defer os.RemoveAll(dir)
			if err := createDir(dir, tc.wants); err != nil {
				t.Fatalf("createDir(): %v", err)
			}

			spec := &specs.LinuxResources{
				Pids: tc.spec,
			}
			ctrlr := pids{}
			if err := ctrlr.set(spec, dir); err != nil {
				t.Fatalf("ctrlr.set(): %v", err)
			}
			checkDir(t, dir, tc.wants)
		})
	}
}

func TestLoadPaths(t *testing.T) {
	for _, tc := range []struct {
		name      string
		cgroups   string
		mountinfo string
		want      map[string]string
		err       string
	}{
		{
			name:      "empty",
			mountinfo: debianMountinfo,
		},
		{
			name:      "abs-path",
			cgroups:   "0:cpu:/path",
			mountinfo: debianMountinfo,
			want:      map[string]string{"cpu": "/path"},
		},
		{
			name:      "rel-path",
			cgroups:   "0:cpu:rel-path",
			mountinfo: debianMountinfo,
			want:      map[string]string{"cpu": "rel-path"},
		},
		{
			name:      "non-controller",
			cgroups:   "0:name=systemd:/path",
			mountinfo: debianMountinfo,
			want:      map[string]string{"systemd": "/path"},
		},
		{
			name:      "unknown-controller",
			cgroups:   "0:ctr:/path",
			mountinfo: debianMountinfo,
			want:      map[string]string{},
		},
		{
			name: "multiple",
			cgroups: "0:cpu:/path0\n" +
				"1:memory:/path1\n" +
				"2::/empty\n",
			mountinfo: debianMountinfo,
			want: map[string]string{
				"cpu":    "/path0",
				"memory": "/path1",
			},
		},
		{
			name:      "missing-field",
			cgroups:   "0:nopath\n",
			mountinfo: debianMountinfo,
			err:       "invalid cgroups file",
		},
		{
			name:      "too-many-fields",
			cgroups:   "0:ctr:/path:extra\n",
			mountinfo: debianMountinfo,
			err:       "invalid cgroups file",
		},
		{
			name: "multiple-malformed",
			cgroups: "0:ctr0:/path0\n" +
				"1:ctr1:/path1\n" +
				"2:\n",
			mountinfo: debianMountinfo,
			err:       "invalid cgroups file",
		},
		{
			name: "nested-cgroup",
			cgroups: "9:memory:/docker/136\n" +
				"2:cpu,cpuacct:/docker/136\n" +
				"1:name=systemd:/docker/136\n" +
				"0::/system.slice/containerd.service\n",
			mountinfo: dindMountinfo,
			// we want relative path to /sys/fs/cgroup inside the nested container.
			// Subcroup inside the container will be created at /sys/fs/cgroup/cpu
			// This will be /sys/fs/cgroup/cpu/docker/136/CGROUP_NAME
			// outside the container
			want: map[string]string{
				"memory":  ".",
				"cpu":     ".",
				"cpuacct": ".",
				"systemd": ".",
			},
		},
		{
			name:      "nested-cgroup-submount",
			cgroups:   "9:memory:/docker/136/test",
			mountinfo: dindMountinfo,
			want: map[string]string{
				"memory": "test",
			},
		},
		{
			name:      "invalid-mount-info",
			cgroups:   "0:memory:/path",
			mountinfo: "41 35 0:36 / /sys/fs/cgroup/memory rw shared:16 - invalid",
			want: map[string]string{
				"memory": "/path",
			},
		},
		{
			name:      "invalid-rel-path-in-proc-cgroup",
			cgroups:   "9:memory:invalid",
			mountinfo: dindMountinfo,
			err:       "can't make invalid relative to /docker/136",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := strings.NewReader(tc.cgroups)
			mountinfo := strings.NewReader(tc.mountinfo)
			got, err := loadPathsHelper(r, mountinfo)
			if len(tc.err) == 0 {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Fatalf("Wrong error message, want: *%s*, got: %v", tc.err, err)
			}
			for key, vWant := range tc.want {
				vGot, ok := got[key]
				if !ok {
					t.Errorf("Missing controller %q", key)
				}
				if vWant != vGot {
					t.Errorf("Wrong controller %q value, want: %q, got: %q", key, vWant, vGot)
				}
				delete(got, key)
			}
			for k, v := range got {
				t.Errorf("Unexpected controller %q: %q", k, v)
			}
		})
	}
}

func TestOptional(t *testing.T) {
	for _, tc := range []struct {
		name  string
		ctrlr controller
		spec  *specs.LinuxResources
		err   string
	}{
		{
			name:  "pids",
			ctrlr: &pids{},
			spec:  &specs.LinuxResources{Pids: &specs.LinuxPids{Limit: 1}},
			err:   "Pids.Limit set but pids cgroup controller not found",
		},
		{
			name:  "net-cls",
			ctrlr: &networkClass{},
			spec:  &specs.LinuxResources{Network: &specs.LinuxNetwork{ClassID: uint32Ptr(1)}},
			err:   "Network.ClassID set but net_cls cgroup controller not found",
		},
		{
			name:  "net-prio",
			ctrlr: &networkPrio{},
			spec: &specs.LinuxResources{Network: &specs.LinuxNetwork{
				Priorities: []specs.LinuxInterfacePriority{
					{Name: "foo", Priority: 1},
				},
			}},
			err: "Network.Priorities set but net_prio cgroup controller not found",
		},
		{
			name:  "hugetlb",
			ctrlr: &hugeTLB{},
			spec: &specs.LinuxResources{HugepageLimits: []specs.LinuxHugepageLimit{
				{Pagesize: "1", Limit: 2},
			}},
			err: "HugepageLimits set but hugetlb cgroup controller not found",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ctrlr.skip(tc.spec)
			if err == nil {
				t.Fatalf("ctrlr.skip() didn't fail")
			}
			if !strings.Contains(err.Error(), tc.err) {
				t.Errorf("ctrlr.skip() want: *%s*, got: %q", tc.err, err)
			}
		})
	}
}
