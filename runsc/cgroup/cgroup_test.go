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
24 31 0:22 / /sys rw,nosuid,nodev,noexec,relatime shared:7 - sysfs sysfs rw
25 31 0:23 / /proc rw,nosuid,nodev,noexec,relatime shared:15 - proc proc rw
26 31 0:5 / /dev rw,nosuid,noexec,relatime shared:2 - devtmpfs udev rw,size=16294760k,nr_inodes=4073690,mode=755
27 26 0:24 / /dev/pts rw,nosuid,noexec,relatime shared:3 - devpts devpts rw,gid=5,mode=620,ptmxmode=000
28 31 0:25 / /run rw,nosuid,nodev,noexec,relatime shared:5 - tmpfs tmpfs rw,size=3268816k,mode=755
31 1 253:1 / / rw,noatime shared:1 - ext4 /dev/mapper/data-root rw,errors=remount-ro
32 24 0:7 / /sys/kernel/security rw,nosuid,nodev,noexec,relatime shared:8 - securityfs securityfs rw
33 26 0:28 / /dev/shm rw,nosuid,nodev shared:4 - tmpfs tmpfs rw
34 28 0:29 / /run/lock rw,nosuid,nodev,noexec,relatime shared:6 - tmpfs tmpfs rw,size=5120k
35 24 0:30 / /sys/fs/cgroup ro,nosuid,nodev,noexec shared:9 - tmpfs tmpfs ro,size=4096k,nr_inodes=1024,mode=755
36 35 0:31 / /sys/fs/cgroup/unified rw,nosuid,nodev,noexec,relatime shared:10 - cgroup2 cgroup2 rw,nsdelegate
37 35 0:32 / /sys/fs/cgroup/systemd rw,nosuid,nodev,noexec,relatime shared:11 - cgroup cgroup rw,xattr,name=systemd
38 24 0:33 / /sys/fs/pstore rw,nosuid,nodev,noexec,relatime shared:12 - pstore pstore rw
39 24 0:34 / /sys/firmware/efi/efivars rw,nosuid,nodev,noexec,relatime shared:13 - efivarfs efivarfs rw
40 24 0:35 / /sys/fs/bpf rw,nosuid,nodev,noexec,relatime shared:14 - bpf none rw,mode=700
41 35 0:36 / /sys/fs/cgroup/cpu,cpuacct rw,nosuid,nodev,noexec,relatime shared:16 - cgroup cgroup rw,cpu,cpuacct
42 35 0:37 / /sys/fs/cgroup/freezer rw,nosuid,nodev,noexec,relatime shared:17 - cgroup cgroup rw,freezer
43 35 0:38 / /sys/fs/cgroup/hugetlb rw,nosuid,nodev,noexec,relatime shared:18 - cgroup cgroup rw,hugetlb
44 35 0:39 / /sys/fs/cgroup/cpuset rw,nosuid,nodev,noexec,relatime shared:19 - cgroup cgroup rw,cpuset
45 35 0:40 / /sys/fs/cgroup/net_cls,net_prio rw,nosuid,nodev,noexec,relatime shared:20 - cgroup cgroup rw,net_cls,net_prio
46 35 0:41 / /sys/fs/cgroup/pids rw,nosuid,nodev,noexec,relatime shared:21 - cgroup cgroup rw,pids
47 35 0:42 / /sys/fs/cgroup/perf_event rw,nosuid,nodev,noexec,relatime shared:22 - cgroup cgroup rw,perf_event
48 35 0:43 / /sys/fs/cgroup/memory rw,nosuid,nodev,noexec,relatime shared:23 - cgroup cgroup rw,memory
49 35 0:44 / /sys/fs/cgroup/blkio rw,nosuid,nodev,noexec,relatime shared:24 - cgroup cgroup rw,blkio
50 35 0:45 / /sys/fs/cgroup/devices rw,nosuid,nodev,noexec,relatime shared:25 - cgroup cgroup rw,devices
51 35 0:46 / /sys/fs/cgroup/rdma rw,nosuid,nodev,noexec,relatime shared:26 - cgroup cgroup rw,rdma
52 25 0:47 / /proc/sys/fs/binfmt_misc rw,relatime shared:27 - autofs systemd-1 rw,fd=28,pgrp=1,timeout=0,minproto=5,maxproto=5,direct,pipe_ino=23671
53 26 0:20 / /dev/mqueue rw,nosuid,nodev,noexec,relatime shared:28 - mqueue mqueue rw
54 26 0:48 / /dev/hugepages rw,relatime shared:29 - hugetlbfs hugetlbfs rw,pagesize=2M
55 24 0:6 / /sys/kernel/debug rw,nosuid,nodev,noexec,relatime shared:30 - debugfs debugfs rw
56 24 0:11 / /sys/kernel/tracing rw,nosuid,nodev,noexec,relatime shared:31 - tracefs tracefs rw
57 24 0:49 / /sys/fs/fuse/connections rw,nosuid,nodev,noexec,relatime shared:32 - fusectl fusectl rw
58 24 0:21 / /sys/kernel/config rw,nosuid,nodev,noexec,relatime shared:33 - configfs configfs rw
`

var dindMountinfo = `
1300 1252 0:55 / / rw,relatime master:665 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/4FX5VCS5UM46IN3FMFIQ5Z3UPH:/var/lib/docker/overlay2/l/3LYKDG2G7WMWFN7KKKZJNQB7AO:/var/lib/docker/overlay2/l/X4N4WIO64ERVFM35SGMCXMW5HX:/var/lib/docker/overlay2/l/WLV7ZCKK2OJHEADMAKFKCITYVA:/var/lib/docker/overlay2/l/RB6D5GFMA2JVMWGG5N7ZWEXQII:/var/lib/docker/overlay2/l/U3TWA3AQ6HAGG67SIDEBFJ2JJF:/var/lib/docker/overlay2/l/WC6XFGD7YWGQLOSNQWLPVCCQX2:/var/lib/docker/overlay2/l/DW235S3RJLDSGSNXHL2U3WVCCL:/var/lib/docker/overlay2/l/D4YM6NOOKDBR7QRG6L6LWHQUZK:/var/lib/docker/overlay2/l/YRLU243KN3AMWHZVPNUMGYD75M:/var/lib/docker/overlay2/l/IISAPU47O4JN6JC5I4A43SFWM7:/var/lib/docker/overlay2/l/UVIPA27BMQWS6NRHHU3QEI5YZT,upperdir=/var/lib/docker/overlay2/749721f78c6ec4d47aacbf01f29a4bd495b1b7a2e9b861fb10f14126d359fd04/diff,workdir=/var/lib/docker/overlay2/749721f78c6ec4d47aacbf01f29a4bd495b1b7a2e9b861fb10f14126d359fd04/work
1301 1300 0:59 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
1302 1300 0:61 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
1303 1302 0:62 / /dev/pts rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
1304 1300 0:63 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro
1305 1304 0:64 / /sys/fs/cgroup rw,nosuid,nodev,noexec,relatime - tmpfs tmpfs rw,mode=755
1306 1305 0:32 /docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51 /sys/fs/cgroup/systemd ro,nosuid,nodev,noexec,relatime master:11 - cgroup cgroup rw,xattr,name=systemd
1307 1305 0:36 /docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51 /sys/fs/cgroup/cpu,cpuacct ro,nosuid,nodev,noexec,relatime master:16 - cgroup cgroup rw,cpu,cpuacct
1308 1305 0:37 /docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51 /sys/fs/cgroup/freezer ro,nosuid,nodev,noexec,relatime master:17 - cgroup cgroup rw,freezer
1309 1305 0:38 /docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51 /sys/fs/cgroup/hugetlb ro,nosuid,nodev,noexec,relatime master:18 - cgroup cgroup rw,hugetlb
1310 1305 0:39 /docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51 /sys/fs/cgroup/cpuset ro,nosuid,nodev,noexec,relatime master:19 - cgroup cgroup rw,cpuset
1311 1305 0:40 /docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51 /sys/fs/cgroup/net_cls,net_prio ro,nosuid,nodev,noexec,relatime master:20 - cgroup cgroup rw,net_cls,net_prio
1312 1305 0:41 /docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51 /sys/fs/cgroup/pids ro,nosuid,nodev,noexec,relatime master:21 - cgroup cgroup rw,pids
1313 1305 0:42 /docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51 /sys/fs/cgroup/perf_event ro,nosuid,nodev,noexec,relatime master:22 - cgroup cgroup rw,perf_event
1314 1305 0:43 /docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51 /sys/fs/cgroup/memory ro,nosuid,nodev,noexec,relatime master:23 - cgroup cgroup rw,memory
1316 1305 0:44 /docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51 /sys/fs/cgroup/blkio ro,nosuid,nodev,noexec,relatime master:24 - cgroup cgroup rw,blkio
1317 1305 0:45 /docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51 /sys/fs/cgroup/devices ro,nosuid,nodev,noexec,relatime master:25 - cgroup cgroup rw,devices
1318 1305 0:46 / /sys/fs/cgroup/rdma ro,nosuid,nodev,noexec,relatime master:26 - cgroup cgroup rw,rdma
1319 1302 0:58 / /dev/mqueue rw,nosuid,nodev,noexec,relatime - mqueue mqueue rw
1320 1302 0:65 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k
1321 1300 253:1 /var/lib/docker/containers/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51/resolv.conf /etc/resolv.conf rw,noatime - ext4 /dev/mapper/data-root rw,errors=remount-ro
1322 1300 253:1 /var/lib/docker/containers/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51/hostname /etc/hostname rw,noatime - ext4 /dev/mapper/data-root rw,errors=remount-ro
1323 1300 253:1 /var/lib/docker/containers/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51/hosts /etc/hosts rw,noatime - ext4 /dev/mapper/data-root rw,errors=remount-ro
1324 1300 253:1 /var/lib/docker/volumes/76f4f27c7bdba8207958a4aed6692c400f98819aa32af1faf38ebb21fcb4bea3/_data /var/lib/docker rw,noatime master:1 - ext4 /dev/mapper/data-root rw,errors=remount-ro
1253 1302 0:62 /0 /dev/console rw,nosuid,noexec,relatime - devpts devpts rw,gid=5,mode=620,ptmxmode=666
1254 1301 0:59 /bus /proc/bus ro,relatime - proc proc rw
1255 1301 0:59 /fs /proc/fs ro,relatime - proc proc rw
1256 1301 0:59 /irq /proc/irq ro,relatime - proc proc rw
1257 1301 0:59 /sys /proc/sys ro,relatime - proc proc rw
1258 1301 0:59 /sysrq-trigger /proc/sysrq-trigger ro,relatime - proc proc rw
1259 1301 0:66 / /proc/asound ro,relatime - tmpfs tmpfs ro
1260 1301 0:67 / /proc/acpi ro,relatime - tmpfs tmpfs ro
1261 1301 0:61 /null /proc/kcore rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
1262 1301 0:61 /null /proc/keys rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
1263 1301 0:61 /null /proc/timer_list rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
1264 1301 0:61 /null /proc/sched_debug rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
1265 1301 0:68 / /proc/scsi ro,relatime - tmpfs tmpfs ro
1266 1304 0:69 / /sys/firmware ro,relatime - tmpfs tmpfs ro
`

func TestUninstallEnoent(t *testing.T) {
	c := Cgroup{
		// set a non-existent name
		Name: "runsc-test-uninstall-656e6f656e740a",
	}
	c.Own = make(map[string]bool)
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
			name:      "abs-path",
			cgroups:   "0:ctr:/path",
			mountinfo: debianMountinfo,
			want:      map[string]string{"ctr": "/path"},
		},
		{
			name:      "rel-path",
			cgroups:   "0:ctr:rel-path",
			mountinfo: debianMountinfo,
			want:      map[string]string{"ctr": "rel-path"},
		},
		{
			name:      "non-controller",
			cgroups:   "0:name=systemd:/path",
			mountinfo: debianMountinfo,
			want:      map[string]string{"systemd": "path"},
		},
		{
			name:      "empty",
			mountinfo: debianMountinfo,
		},
		{
			name: "multiple",
			cgroups: "0:ctr0:/path0\n" +
				"1:ctr1:/path1\n" +
				"2::/empty\n",
			mountinfo: debianMountinfo,
			want: map[string]string{
				"ctr0": "/path0",
				"ctr1": "/path1",
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
			cgroups: `9:memory:/docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51
2:cpu,cpuacct:/docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51
1:name=systemd:/docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51
0::/system.slice/containerd.service`,
			mountinfo: dindMountinfo,
			// we want relative path to /sys/fs/cgroup inside the nested container.
			// Subcroup inside the container will be created at /sys/fs/cgroup/cpu
			// This will be /sys/fs/cgroup/cpu/docker/136811d8fa1136e2746d10f6443c4c787c3cfbab5273270cc3aeeb3a94b3cc51/CGROUP_NAME
			// outside the container
			want: map[string]string{
				"memory":  ".",
				"cpu":     ".",
				"cpuacct": ".",
				"systemd": ".",
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := strings.NewReader(tc.cgroups)
			mountinfo := strings.NewReader(tc.mountinfo)
			got, err := loadPathsHelperWithMountinfo(r, mountinfo)
			if len(tc.err) == 0 {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
			} else if !strings.Contains(err.Error(), tc.err) {
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
