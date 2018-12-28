// Copyright 2018 Google LLC
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
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gvisor.googlesource.com/gvisor/runsc/test/testutil"
)

// TestCgroup sets cgroup options and checks that cgroup was properly configured.
func TestCgroup(t *testing.T) {
	if err := testutil.Pull("alpine"); err != nil {
		t.Fatal("docker pull failed:", err)
	}
	d := testutil.MakeDocker("cgroup-test")

	attrs := []struct {
		arg            string
		ctrl           string
		file           string
		want           string
		skipIfNotFound bool
	}{
		{
			arg:  "--cpu-shares=1000",
			ctrl: "cpu",
			file: "cpu.shares",
			want: "1000",
		},
		{
			arg:  "--cpu-period=2000",
			ctrl: "cpu",
			file: "cpu.cfs_period_us",
			want: "2000",
		},
		{
			arg:  "--cpu-quota=3000",
			ctrl: "cpu",
			file: "cpu.cfs_quota_us",
			want: "3000",
		},
		{
			arg:  "--cpuset-cpus=0",
			ctrl: "cpuset",
			file: "cpuset.cpus",
			want: "0",
		},
		{
			arg:  "--cpuset-mems=0",
			ctrl: "cpuset",
			file: "cpuset.mems",
			want: "0",
		},
		{
			arg:  "--kernel-memory=100MB",
			ctrl: "memory",
			file: "memory.kmem.limit_in_bytes",
			want: "104857600",
		},
		{
			arg:  "--memory=1GB",
			ctrl: "memory",
			file: "memory.limit_in_bytes",
			want: "1073741824",
		},
		{
			arg:  "--memory-reservation=500MB",
			ctrl: "memory",
			file: "memory.soft_limit_in_bytes",
			want: "524288000",
		},
		{
			arg:            "--memory-swap=2GB",
			ctrl:           "memory",
			file:           "memory.memsw.limit_in_bytes",
			want:           "2147483648",
			skipIfNotFound: true, // swap may be disabled on the machine.
		},
		{
			arg:  "--memory-swappiness=5",
			ctrl: "memory",
			file: "memory.swappiness",
			want: "5",
		},
		{
			arg:  "--blkio-weight=750",
			ctrl: "blkio",
			file: "blkio.weight",
			want: "750",
		},
	}

	args := make([]string, 0, len(attrs))
	for _, attr := range attrs {
		args = append(args, attr.arg)
	}

	args = append(args, "alpine", "sleep", "10000")
	if err := d.Run(args...); err != nil {
		t.Fatal("docker create failed:", err)
	}
	defer d.CleanUp()

	gid, err := d.ID()
	if err != nil {
		t.Fatalf("Docker.ID() failed: %v", err)
	}
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
			t.Errorf("arg: %q, cgroup attribute %s/%s, got: %q, want: %q", attr.arg, attr.ctrl, attr.file, got, attr.want)
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
	pid, err := d.SandboxPid()
	if err != nil {
		t.Fatalf("SandboxPid: %v", err)
	}
	for _, ctrl := range controllers {
		path := filepath.Join("/sys/fs/cgroup", ctrl, "docker", gid, "cgroup.procs")
		out, err := ioutil.ReadFile(path)
		if err != nil {
			t.Fatalf("failed to read %q: %v", path, err)
		}
		if got := string(out); !strings.Contains(got, strconv.Itoa(pid)) {
			t.Errorf("cgroup control %s processes, got: %q, want: %q", ctrl, got, pid)
		}
	}
}
