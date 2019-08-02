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

// Binary proctor-python is a utility that facilitates language testing for Pyhton.
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gvisor.dev/gvisor/test/runtimes/common"
)

var (
	dir = os.Getenv("LANG_DIR")
)

type pythonRunner struct {
}

func main() {
	if err := common.LaunchFunc(pythonRunner{}); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}
}

func (p pythonRunner) ListTests() ([]string, error) {
	args := []string{"-m", "test", "--list-tests"}
	cmd := exec.Command(filepath.Join(dir, "python"), args...)
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

func (p pythonRunner) RunTest(test string) error {
	args := []string{"-m", "test", test}
	cmd := exec.Command(filepath.Join(dir, "python"), args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run: %v", err)
	}
	return nil
}
