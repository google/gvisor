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

package root

import (
	"bufio"
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	libcontainercgroups "github.com/opencontainers/runc/libcontainer/cgroups"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/cgroup"
)

func verifyPid(pid int, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var gots []int
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		got, err := strconv.Atoi(scanner.Text())
		if err != nil {
			return err
		}
		if got == pid {
			return nil
		}
		gots = append(gots, got)
	}
	if scanner.Err() != nil {
		return scanner.Err()
	}
	return fmt.Errorf("got: %v, want: %d", gots, pid)
}

func TestMemCgroup(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Start a new container and allocate the specified about of memory.
	allocMemSize := 128 << 20
	allocMemLimit := 2 * allocMemSize

	if err := d.Spawn(ctx, dockerutil.RunOpts{
		Image:  "basic/ubuntu",
		Memory: allocMemLimit, // Must be in bytes.
	}, "python3", "-c", fmt.Sprintf("import time; s = 'a' * %d; time.sleep(100)", allocMemSize)); err != nil {
		t.Fatalf("docker run failed: %v", err)
	}

	// Extract the ID to lookup the cgroup.
	gid := d.ID()
	t.Logf("cgroup ID: %s", gid)

	// Wait when the container will allocate memory.
	memUsage := 0
	start := time.Now()
	for time.Since(start) < 30*time.Second {
		// Sleep for a brief period of time after spawning the
		// container (so that Docker can create the cgroup etc.
		// or after looping below (so the application can start).
		time.Sleep(100 * time.Millisecond)

		var path string

		// Read the cgroup memory limit.
		if libcontainercgroups.IsCgroup2UnifiedMode() {
			path = filepath.Join("/sys/fs/cgroup/docker", gid, "memory.max")
		} else {
			path = filepath.Join("/sys/fs/cgroup/memory/docker", gid, "memory.limit_in_bytes")
		}
		outRaw, err := ioutil.ReadFile(path)
		if err != nil {
			// It's possible that the container does not exist yet.
			continue
		}
		out := strings.TrimSpace(string(outRaw))
		memLimit, err := strconv.Atoi(out)
		if err != nil {
			t.Fatalf("Atoi(%v): %v", out, err)
		}
		if memLimit != allocMemLimit {
			// The group may not have had the correct limit set yet.
			continue
		}

		// Read the cgroup memory usage.
		// cgroupv2 doesn't support max_usage_in_bytes
		if libcontainercgroups.IsCgroup2UnifiedMode() {
			return
		} else {
			path = filepath.Join("/sys/fs/cgroup/memory/docker", gid, "memory.max_usage_in_bytes")
			outRaw, err = ioutil.ReadFile(path)
			if err != nil {
				t.Fatalf("error reading usage: %v", err)
			}
			out = strings.TrimSpace(string(outRaw))
			memUsage, err = strconv.Atoi(out)
			if err != nil {
				t.Fatalf("Atoi(%v): %v", out, err)
			}
			t.Logf("read usage: %v, wanted: %v", memUsage, allocMemSize)

			// Are we done?
			if memUsage >= allocMemSize {
				return
			}
		}
	}

	t.Fatalf("%vMB is less than %vMB", memUsage>>20, allocMemSize>>20)
}

// TestCgroupV1 sets cgroup options and checks that cgroup was properly configured with
// cgroupv1 setup
func TestCgroupV1(t *testing.T) {
	if libcontainercgroups.IsCgroup2UnifiedMode() {
		t.Skip("skipping cgroupv1 attribute testing in cgroupv2 setup")
	}
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// This is not a comprehensive list of attributes.
	//
	// Note that we are specifically missing cpusets, which fail if specified.
	// In any case, it's unclear if cpusets can be reliably tested here: these
	// are often run on a single core virtual machine, and there is only a single
	// CPU available in our current set, and every container's set.
	attrs := []struct {
		field          string
		value          int64
		ctrl           string
		file           string
		want           string
		skipIfNotFound bool
	}{
		{
			field: "cpu-shares",
			value: 1000,
			ctrl:  "cpu",
			file:  "cpu.shares",
			want:  "1000",
		},
		{
			field: "cpu-period",
			value: 2000,
			ctrl:  "cpu",
			file:  "cpu.cfs_period_us",
			want:  "2000",
		},
		{
			field: "cpu-quota",
			value: 3000,
			ctrl:  "cpu",
			file:  "cpu.cfs_quota_us",
			want:  "3000",
		},
		{
			field: "kernel-memory",
			value: 100 << 20,
			ctrl:  "memory",
			file:  "memory.kmem.limit_in_bytes",
			want:  "104857600",
		},
		{
			field: "memory",
			value: 1 << 30,
			ctrl:  "memory",
			file:  "memory.limit_in_bytes",
			want:  "1073741824",
		},
		{
			field: "memory-reservation",
			value: 500 << 20,
			ctrl:  "memory",
			file:  "memory.soft_limit_in_bytes",
			want:  "524288000",
		},
		{
			field:          "memory-swap",
			value:          2 << 30,
			ctrl:           "memory",
			file:           "memory.memsw.limit_in_bytes",
			want:           "2147483648",
			skipIfNotFound: true, // swap may be disabled on the machine.
		},
		{
			field: "memory-swappiness",
			value: 5,
			ctrl:  "memory",
			file:  "memory.swappiness",
			want:  "5",
		},
		{
			field:          "blkio-weight",
			value:          750,
			ctrl:           "blkio",
			file:           "blkio.weight",
			want:           "750",
			skipIfNotFound: true, // blkio groups may not be available.
		},
		{
			field: "pids-limit",
			value: 1000,
			ctrl:  "pids",
			file:  "pids.max",
			want:  "1000",
		},
	}

	// Make configs.
	conf, hostconf, _ := d.ConfigsFrom(dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sleep", "10000")

	// Add Cgroup arguments to configs.
	for _, attr := range attrs {
		switch attr.field {
		case "cpu-shares":
			hostconf.Resources.CPUShares = attr.value
		case "cpu-period":
			hostconf.Resources.CPUPeriod = attr.value
		case "cpu-quota":
			hostconf.Resources.CPUQuota = attr.value
		case "kernel-memory":
			hostconf.Resources.KernelMemory = attr.value
		case "memory":
			hostconf.Resources.Memory = attr.value
		case "memory-reservation":
			hostconf.Resources.MemoryReservation = attr.value
		case "memory-swap":
			hostconf.Resources.MemorySwap = attr.value
		case "memory-swappiness":
			val := attr.value
			hostconf.Resources.MemorySwappiness = &val
		case "blkio-weight":
			hostconf.Resources.BlkioWeight = uint16(attr.value)
		case "pids-limit":
			val := attr.value
			hostconf.Resources.PidsLimit = &val
		}
	}

	// Create container.
	if err := d.CreateFrom(ctx, "basic/alpine", conf, hostconf, nil); err != nil {
		t.Fatalf("create failed with: %v", err)
	}

	// Start container.
	if err := d.Start(ctx); err != nil {
		t.Fatalf("start failed with: %v", err)
	}

	// Lookup the relevant cgroup ID.
	gid := d.ID()
	t.Logf("cgroup ID: %s", gid)

	// Check list of attributes defined above.
	for _, attr := range attrs {
		path := filepath.Join("/sys/fs/cgroup", attr.ctrl, "docker", gid, attr.file)
		out, err := ioutil.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) && attr.skipIfNotFound {
				t.Logf("skipped %s/%s", attr.ctrl, attr.file)
				continue
			}
			t.Fatalf("failed to read %q: %v", path, err)
		}
		if got := strings.TrimSpace(string(out)); got != attr.want {
			t.Errorf("field: %q, cgroup attribute %s/%s, got: %q, want: %q", attr.field, attr.ctrl, attr.file, got, attr.want)
		}
	}

	// Check that sandbox is inside cgroup.
	controllers := []string{
		"blkio",
		"cpu",
		"cpuset",
		"memory",
		"net_cls",
		"net_prio",
		"devices",
		"freezer",
		"perf_event",
		"pids",
		"systemd",
	}
	pid, err := d.SandboxPid(ctx)
	if err != nil {
		t.Fatalf("SandboxPid: %v", err)
	}
	for _, ctrl := range controllers {
		path := filepath.Join("/sys/fs/cgroup", ctrl, "docker", gid, "cgroup.procs")
		if err := verifyPid(pid, path); err != nil {
			t.Errorf("cgroup control %q processes: %v", ctrl, err)
		}
	}
}

// TestCgroupV2 sets cgroup options and checks that cgroup was properly configured with
// cgroupv2 setup
func TestCgroupV2(t *testing.T) {
	if !libcontainercgroups.IsCgroup2UnifiedMode() {
		t.Skip("skipping cgroupv2 attribute testing in cgroupv1 setup")
	}
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// This is not a comprehensive list of attributes.
	//
	// Note that we are specifically missing cpusets, which fail if specified.
	// In any case, it's unclear if cpusets can be reliably tested here: these
	// are often run on a single core virtual machine, and there is only a single
	// CPU available in our current set, and every container's set.
	attrs := []struct {
		field          string
		value          int64
		file           string
		want           string
		skipIfNotFound bool
	}{
		{
			field: "cpu-shares",
			value: 1000,
			file:  "cpu.weight",
			want:  fmt.Sprintf("%d", libcontainercgroups.ConvertCPUSharesToCgroupV2Value(1000)),
		},
		{
			field: "cpu-period",
			value: 2000,
			file:  "cpu.max",
			want:  "max 2000",
		},
		{
			field: "memory",
			value: 1 << 30,
			file:  "memory.max",
			want:  "1073741824",
		},
		{
			field: "memory-reservation",
			value: 500 << 20,
			file:  "memory.low",
			want:  "524288000",
		},
		{
			field: "memory-swap",
			value: 1 << 31,
			file:  "memory.swap.max",
			// memory.swap.max is only the swap value, unlike cgroupv1
			want:           fmt.Sprintf("%d", 1<<31-1<<30),
			skipIfNotFound: true, // swap may be disabled on the machine.
		},
		// FIXME: enable blkio weight. Currently it's setting wrong value, see
		// https://github.com/opencontainers/runc/pull/2786
		// {
		//   field:          "blkio-weight",
		//   value:          750,
		//   file:           "io.bfq.weight",
		//   want:           fmt.Sprintf("%d", libcontainercgroups.ConvertBlkIOToCgroupV2Value(750)),
		//   skipIfNotFound: true, // blkio groups may not be available.
		// },
		{
			field: "pids-limit",
			value: 1000,
			file:  "pids.max",
			want:  "1000",
		},
	}

	// Make configs.
	conf, hostconf, _ := d.ConfigsFrom(dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sleep", "10000")

	// Add Cgroup arguments to configs.
	for _, attr := range attrs {
		switch attr.field {
		case "cpu-shares":
			hostconf.Resources.CPUShares = attr.value
		case "cpu-period":
			hostconf.Resources.CPUPeriod = attr.value
		case "cpu-quota":
			hostconf.Resources.CPUQuota = attr.value
		case "kernel-memory":
			hostconf.Resources.KernelMemory = attr.value
		case "memory":
			hostconf.Resources.Memory = attr.value
		case "memory-reservation":
			hostconf.Resources.MemoryReservation = attr.value
		case "memory-swap":
			hostconf.Resources.MemorySwap = attr.value
		case "memory-swappiness":
			val := attr.value
			hostconf.Resources.MemorySwappiness = &val
		case "blkio-weight":
			// detect existence of io.bfq.weight as this is not always loaded
			_, err := ioutil.ReadFile(filepath.Join("/sys/fs/cgroup", "docker", attr.file))
			if err == nil || !attr.skipIfNotFound {
				hostconf.Resources.BlkioWeight = uint16(attr.value)
			}
		case "pids-limit":
			val := attr.value
			hostconf.Resources.PidsLimit = &val
		}
	}

	// Create container.
	if err := d.CreateFrom(ctx, "basic/alpine", conf, hostconf, nil); err != nil {
		t.Fatalf("create failed with: %v", err)
	}

	// Start container.
	if err := d.Start(ctx); err != nil {
		t.Fatalf("start failed with: %v", err)
	}

	// Lookup the relevant cgroup ID.
	gid := d.ID()
	t.Logf("cgroup ID: %s", gid)

	// Check list of attributes defined above.
	for _, attr := range attrs {
		path := filepath.Join("/sys/fs/cgroup", "docker", gid, attr.file)
		out, err := ioutil.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) && attr.skipIfNotFound {
				t.Logf("skipped %s", attr.file)
				continue
			}
			t.Fatalf("failed to read %q: %v", path, err)
		}
		if got := strings.TrimSpace(string(out)); got != attr.want {
			t.Errorf("field: %q, cgroup attribute %s, got: %q, want: %q", attr.field, attr.file, got, attr.want)
		}
	}

	// Check that sandbox is inside cgroup.
	pid, err := d.SandboxPid(ctx)
	if err != nil {
		t.Fatalf("SandboxPid: %v", err)
	}
	path := filepath.Join("/sys/fs/cgroup", "docker", gid, "cgroup.procs")
	if err := verifyPid(pid, path); err != nil {
		t.Errorf("cgroup control processes: %v", err)
	}
}

// TestCgroupParent sets the "CgroupParent" option and checks that the child and parent's
// cgroups are created correctly relative to each other.
func TestCgroupParent(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	// Construct a known cgroup name.
	parent := testutil.RandomID("runsc-")
	conf, hostconf, _ := d.ConfigsFrom(dockerutil.RunOpts{
		Image: "basic/alpine",
	}, "sleep", "10000")
	hostconf.Resources.CgroupParent = parent

	if err := d.CreateFrom(ctx, "basic/alpine", conf, hostconf, nil); err != nil {
		t.Fatalf("create failed with: %v", err)
	}

	if err := d.Start(ctx); err != nil {
		t.Fatalf("start failed with: %v", err)
	}

	// Extract the ID to look up the cgroup.
	gid := d.ID()
	t.Logf("cgroup ID: %s", gid)

	// Check that sandbox is inside cgroup.
	pid, err := d.SandboxPid(ctx)
	if err != nil {
		t.Fatalf("SandboxPid: %v", err)
	}

	// Finds cgroup for the sandbox's parent process to check that cgroup is
	// created in the right location relative to the parent.
	cmd := fmt.Sprintf("grep PPid: /proc/%d/status | sed 's/PPid:\\s//'", pid)
	ppid, err := exec.Command("bash", "-c", cmd).CombinedOutput()
	if err != nil {
		t.Fatalf("Executing %q: %v", cmd, err)
	}
	cgroups, err := cgroup.LoadPaths(strings.TrimSpace(string(ppid)))
	if err != nil {
		t.Fatalf("cgroup.LoadPath(%s): %v", ppid, err)
	}
	var path string
	if libcontainercgroups.IsCgroup2UnifiedMode() {
		// Because parent is not absolute, cgroup v2 code in libcontainer will place it
		// under the parent of the current execution process. The container manager
		// is containerd which lives in /system.slice/containerd.service, so its parent
		// is system.slice
		dir := filepath.Dir(cgroups["cgroup2"])
		path = filepath.Join("/sys/fs/cgroup/", dir, parent, gid, "cgroup.procs")
	} else {
		path = filepath.Join("/sys/fs/cgroup/", cgroups["memory"], parent, gid, "cgroup.procs")
	}
	if err := verifyPid(pid, path); err != nil {
		t.Errorf("cgroup control %q processes: %v", "memory", err)
	}
}
