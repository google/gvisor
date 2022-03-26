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
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/test/runtimes/proctor/lib"
)

var (
	runtime   = flag.String("runtime", "", "name of runtime")
	list      = flag.Bool("list", false, "list all available tests")
	testNames = flag.String("tests", "", "run a subset of the available tests")
	pause     = flag.Bool("pause", false, "cause container to pause indefinitely, reaping any zombie children")
	timeout   = flag.Duration("timeout", 90*time.Minute, "batch timeout")
)

// setNumFilesLimit changes the NOFILE soft rlimit if it is too high.
func setNumFilesLimit() error {
	// In docker containers, the default value of the NOFILE limit is
	// 1048576. A few runtime tests (e.g. python:test_subprocess)
	// enumerates all possible file descriptors and these tests can fail by
	// timeout if the NOFILE limit is too high. On gVisor, syscalls are
	// slower so these tests will need even more time to pass.
	const nofile = 32768
	rLimit := unix.Rlimit{}
	err := unix.Getrlimit(unix.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return fmt.Errorf("failed to get RLIMIT_NOFILE: %v", err)
	}
	if rLimit.Cur > nofile {
		rLimit.Cur = nofile
		err := unix.Setrlimit(unix.RLIMIT_NOFILE, &rLimit)
		if err != nil {
			return fmt.Errorf("failed to set RLIMIT_NOFILE: %v", err)
		}
	}
	return nil
}

func main() {
	flag.Parse()

	if *pause {
		lib.PauseAndReap()
		panic("pauseAndReap should never return")
	}

	if *runtime == "" {
		log.Fatalf("runtime flag must be provided")
	}

	timer := time.NewTimer(*timeout)

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

	// heartbeat
	go func() {
		for {
			time.Sleep(15 * time.Second)
			log.Println("Proctor checking in " + time.Now().String())
		}
	}()

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

	if err := setNumFilesLimit(); err != nil {
		log.Fatalf("%v", err)
	}

	// Run tests.
	cmds := tr.TestCmds(tests)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-done:
			return
		case <-timer.C:
			log.Println("The timeout duration is exceeded")
			killed := false
			for _, cmd := range cmds {
				p := cmd.Process
				if p == nil || cmd.ProcessState != nil {
					continue
				}
				pid := p.Pid
				if pid > 0 {
					unix.Kill(pid, unix.SIGTERM)
					killed = true
				}
			}
			if killed {
				// Let tests to handle signals
				time.Sleep(5 * time.Second)
			}
			panic("FAIL: The timeout duration is exceeded")
		}
	}()
	for _, cmd := range cmds {
		cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
		if err := cmd.Run(); err != nil {
			log.Fatalf("FAIL: %v", err)
		}
	}
}
