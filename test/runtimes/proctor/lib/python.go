// Copyright 2019 The gVisor Authors.
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

package lib

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// pythonRunner implements TestRunner for Python.
type pythonRunner struct{}

var _ TestRunner = pythonRunner{}

// ListTests implements TestRunner.ListTests.
func (pythonRunner) ListTests() ([]string, error) {
	args := []string{"-m", "test", "--list-tests"}
	cmd := exec.Command("./python", args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to list: %v", err)
	}
	var toolSlice []string
	for _, test := range strings.Split(string(out), "\n") {
		toolSlice = append(toolSlice, test)
	}
	return toolSlice, nil
}

// TestCmds implements TestRunner.TestCmds.
func (pythonRunner) TestCmds(tests []string) []*exec.Cmd {
	args := append([]string{"-m", "test"}, tests...)
	return []*exec.Cmd{exec.Command("./python", args...)}
}
