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

// Binary proctor-php is a utility that facilitates language testing for PHP.
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"

	"gvisor.dev/gvisor/test/runtimes/common"
)

var (
	dir       = os.Getenv("LANG_DIR")
	testRegEx = regexp.MustCompile(`^.+\.phpt$`)
)

type phpRunner struct {
}

func main() {
	if err := common.LaunchFunc(phpRunner{}); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}
}

func (p phpRunner) ListTests() ([]string, error) {
	testSlice, err := common.Search(dir, testRegEx)
	if err != nil {
		return nil, err
	}
	return testSlice, nil
}

func (p phpRunner) RunTest(test string) error {
	args := []string{"test", "TESTS=" + test}
	cmd := exec.Command("make", args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run: %v", err)
	}
	return nil
}
