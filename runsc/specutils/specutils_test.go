// Copyright 2018 Google Inc.
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
	if !strings.Contains(err.Error(), "not running") {
		t.Errorf("ProcessWaitReady got: %v, expected: not running", err)
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
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("ProcessWaitReady got: %v, expected: timed out", err)
	}
	cmd.Process.Kill()
}
