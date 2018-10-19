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

package specutils

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
	"time"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestWaitForReadyHappy(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "1000")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() failed, err: %v", err)
	}
	defer cmd.Wait()

	var count int
	err := WaitForReady(cmd.Process.Pid, 5*time.Second, func() (bool, error) {
		if count < 3 {
			count++
			return false, nil
		}
		return true, nil
	})
	if err != nil {
		t.Errorf("ProcessWaitReady got: %v, expected: nil", err)
	}
	cmd.Process.Kill()
}

func TestWaitForReadyFail(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "1000")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() failed, err: %v", err)
	}
	defer cmd.Wait()

	var count int
	err := WaitForReady(cmd.Process.Pid, 5*time.Second, func() (bool, error) {
		if count < 3 {
			count++
			return false, nil
		}
		return false, fmt.Errorf("Fake error")
	})
	if err == nil {
		t.Errorf("ProcessWaitReady got: nil, expected: error")
	}
	cmd.Process.Kill()
}

func TestWaitForReadyNotRunning(t *testing.T) {
	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() failed, err: %v", err)
	}
	defer cmd.Wait()

	err := WaitForReady(cmd.Process.Pid, 5*time.Second, func() (bool, error) {
		return false, nil
	})
	if err != nil && !strings.Contains(err.Error(), "terminated") {
		t.Errorf("ProcessWaitReady got: %v, expected: process terminated", err)
	}
	if err == nil {
		t.Errorf("ProcessWaitReady incorrectly succeeded")
	}
}

func TestWaitForReadyTimeout(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "1000")
	if err := cmd.Start(); err != nil {
		t.Fatalf("cmd.Start() failed, err: %v", err)
	}
	defer cmd.Wait()

	err := WaitForReady(cmd.Process.Pid, 50*time.Millisecond, func() (bool, error) {
		return false, nil
	})
	if !strings.Contains(err.Error(), "not running yet") {
		t.Errorf("ProcessWaitReady got: %v, expected: not running yet", err)
	}
	cmd.Process.Kill()
}

func TestSpecInvalid(t *testing.T) {
	for _, test := range []struct {
		name  string
		spec  specs.Spec
		error string
	}{
		{
			name: "valid",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Mounts: []specs.Mount{
					{
						Source:      "src",
						Destination: "/dst",
					},
				},
			},
			error: "",
		},
		{
			name: "valid+warning",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
					// This is normally set by docker and will just cause warnings to be logged.
					ApparmorProfile: "someprofile",
				},
				// This is normally set by docker and will just cause warnings to be logged.
				Linux: &specs.Linux{Seccomp: &specs.LinuxSeccomp{}},
			},
			error: "",
		},
		{
			name: "no root",
			spec: specs.Spec{
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
			},
			error: "must be defined",
		},
		{
			name: "empty root",
			spec: specs.Spec{
				Root: &specs.Root{},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
			},
			error: "must be defined",
		},
		{
			name: "no process",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
			},
			error: "must be defined",
		},
		{
			name: "empty args",
			spec: specs.Spec{
				Root:    &specs.Root{Path: "/"},
				Process: &specs.Process{},
			},
			error: "must be defined",
		},
		{
			name: "selinux",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args:         []string{"/bin/true"},
					SelinuxLabel: "somelabel",
				},
			},
			error: "is not supported",
		},
		{
			name: "solaris",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Solaris: &specs.Solaris{},
			},
			error: "is not supported",
		},
		{
			name: "windows",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Windows: &specs.Windows{},
			},
			error: "is not supported",
		},
		{
			name: "relative mount destination",
			spec: specs.Spec{
				Root: &specs.Root{Path: "/"},
				Process: &specs.Process{
					Args: []string{"/bin/true"},
				},
				Mounts: []specs.Mount{
					{
						Source:      "src",
						Destination: "dst",
					},
				},
			},
			error: "must be an absolute path",
		},
	} {
		err := ValidateSpec(&test.spec)
		if len(test.error) == 0 {
			if err != nil {
				t.Errorf("ValidateSpec(%q) failed, err: %v", test.name, err)
			}
		} else {
			if err == nil || !strings.Contains(err.Error(), test.error) {
				t.Errorf("ValidateSpec(%q) wrong error, got: %v, want: .*%s.*", test.name, err, test.error)
			}
		}
	}
}
