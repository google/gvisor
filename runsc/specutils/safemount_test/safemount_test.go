// Copyright 2021 The gVisor Authors.
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

package safemount_test

import (
	"os"
	"os/exec"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

func TestSafeMount(t *testing.T) {
	// We run the actual tests in another process, as we need CAP_SYS_ADMIN to
	// call mount(2). The new process runs in its own user and mount namespaces.
	runner, err := testutil.FindFile("runsc/specutils/safemount_test/safemount_runner")
	if err != nil {
		t.Fatalf("failed to find test runner binary: %v", err)
	}
	cmd := exec.Command(runner, t.TempDir())
	cmd.SysProcAttr = &unix.SysProcAttr{
		Cloneflags: unix.CLONE_NEWNS | unix.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
		Credential: &syscall.Credential{
			Uid: 0,
			Gid: 0,
		},
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed running %s with error: %v\ntest output:\n%s", cmd, err, output)
	}
}
