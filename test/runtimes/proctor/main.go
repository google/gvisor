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

// Binary proctor runs the test for a particular runtime. It is meant to be
// included in Docker images for all runtime tests.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"gvisor.dev/gvisor/test/runtimes/proctor/lib"
)

var (
	runtime   = flag.String("runtime", "", "name of runtime")
	list      = flag.Bool("list", false, "list all available tests")
	testNames = flag.String("tests", "", "run a subset of the available tests")
	pause     = flag.Bool("pause", false, "cause container to pause indefinitely, reaping any zombie children")
)

func main() {
	flag.Parse()

	if *pause {
		lib.PauseAndReap()
		panic("pauseAndReap should never return")
	}

	if *runtime == "" {
		log.Fatalf("runtime flag must be provided")
	}

	tr, err := lib.TestRunnerForRuntime(*runtime)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// List tests.
	if *list {
		tests, err := tr.ListTests()
		if err != nil {
			log.Fatalf("failed to list tests: %v", err)
		}
		for _, test := range tests {
			fmt.Println(test)
		}
		return
	}

	var tests []string
	if *testNames == "" {
		// Run every test.
		tests, err = tr.ListTests()
		if err != nil {
			log.Fatalf("failed to get all tests: %v", err)
		}
	} else {
		// Run subset of test.
		tests = strings.Split(*testNames, ",")
	}

	// Run tests.
	cmds := tr.TestCmds(tests)
	for _, cmd := range cmds {
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatalf("FAIL: %v", err)
		}
	}
}
