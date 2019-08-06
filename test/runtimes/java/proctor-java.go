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

// Binary proctor-java is a utility that facilitates language testing for Java.
package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"gvisor.dev/gvisor/test/runtimes/common"
)

var (
	dir      = os.Getenv("LANG_DIR")
	hash     = os.Getenv("LANG_HASH")
	jtreg    = filepath.Join(dir, "jtreg/bin/jtreg")
	exclDirs = regexp.MustCompile(`(^(sun\/security)|(java\/util\/stream)|(java\/time)| )`)
)

type javaRunner struct {
}

func main() {
	if err := common.LaunchFunc(javaRunner{}); err != nil {
		log.Fatalf("Failed to start: %v", err)
	}
}

func (j javaRunner) ListTests() ([]string, error) {
	args := []string{
		"-dir:/root/jdk11-" + hash + "/test/jdk",
		"-ignore:quiet",
		"-a",
		"-listtests",
		":jdk_core",
		":jdk_svc",
		":jdk_sound",
		":jdk_imageio",
	}
	cmd := exec.Command(jtreg, args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("jtreg -listtests : %v", err)
	}
	var testSlice []string
	for _, test := range strings.Split(string(out), "\n") {
		if !exclDirs.MatchString(test) {
			testSlice = append(testSlice, test)
		}
	}
	return testSlice, nil
}

func (j javaRunner) RunTest(test string) error {
	args := []string{"-noreport", "-dir:/root/jdk11-" + hash + "/test/jdk", test}
	cmd := exec.Command(jtreg, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to run: %v", err)
	}
	return nil
}
