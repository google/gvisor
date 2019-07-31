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
	"regexp"

	"gvisor.dev/gvisor/test/runtimes/common"
)

var (
	dir       = os.Getenv("LANG_DIR")
	testRegEx = regexp.MustCompile(`^test_.+\.py$`)
)

type pythonRunner struct {
}

func main() {
	if err := common.LaunchFunc(pythonRunner{}); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}
}

func (p pythonRunner) ListTests() ([]string, error) {
	var testSlice []string
	root := filepath.Join(dir, "Lib/test")

	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		name := filepath.Base(path)

		if info.IsDir() || !testRegEx.MatchString(name) {
			return nil
		}

		relPath, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		testSlice = append(testSlice, relPath)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("walking %q: %v", root, err)
	}

	return testSlice, nil
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
