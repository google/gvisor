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
	runtime           = flag.String("runtime", "", "name of runtime")
	list              = flag.Bool("list", false, "list all available tests")
	testNames         = flag.String("tests", "", "run a subset of the available tests")
	pause             = flag.Bool("pause", false, "cause container to pause indefinitely, reaping any zombie children")
	timeout           = flag.Duration("timeout", 90*time.Minute, "batch timeout")
	perTestTimeout    = flag.Duration("per_test_timeout", 20*time.Minute, "per-test timeout (a value of 0 disables per-test timeouts)")
	runsPerTest       = flag.Int("runs_per_test", 1, "number of times to run each test (a value of 0 is the same as a value of 1, i.e. running once)")
	flakyIsError      = flag.Bool("flaky_is_error", true, "if true, when running with multiple --runs_per_test, tests with inconsistent status will result in a failure status code for the batch; if false, they will be considered as passing")
	flakyShortCircuit = flag.Bool("flaky_short_circuit", true, "if true, when running with multiple --runs_per_test and a test is detected as flaky, exit immediately rather than running all --runs_per_test")
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
			log.Println("The batch timeout duration is exceeded")
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
			panic("FAIL: The batch timeout duration is exceeded")
		}
	}()
	numIterations := *runsPerTest
	if numIterations == 0 {
		numIterations = 1
	}
	for _, cmd := range cmds {
		iterations := 0
		successes := 0
		var firstFailure error
		for iteration := 1; iteration <= *runsPerTest; iteration++ {
			// Make a copy of the command, as the same exec.Cmd object cannot be started multiple times.
			cmdCopy := *cmd

			// Handle test timeout.
			testDone := make(chan struct{})
			testTimedOutCh := make(chan bool, 1)
			if *perTestTimeout != 0 {
				go func() {
					timer := time.NewTimer(*perTestTimeout)
					defer timer.Stop()
					select {
					case <-timer.C:
						testTimedOutCh <- true
						cmdCopy.Process.Kill()
					case <-done:
						testTimedOutCh <- false
					case <-testDone:
						testTimedOutCh <- false
					}
				}()
			}

			// Run the test.
			cmdCopy.Stdout, cmdCopy.Stderr = os.Stdout, os.Stderr
			testErr := cmdCopy.Run()
			close(testDone)
			if <-testTimedOutCh {
				testErr = fmt.Errorf("test timed out after %v", *perTestTimeout)
			}

			// Tally result.
			iterations++
			if testErr == nil {
				successes++
			} else if firstFailure == nil {
				firstFailure = testErr
			}
			if *flakyShortCircuit && successes > 0 && firstFailure != nil {
				break
			}
		}
		if successes > 0 && firstFailure != nil {
			// Test is flaky.
			if *flakyIsError {
				log.Fatalf("FLAKY: %v (%d failures out of %d)", firstFailure, iterations-successes, iterations)
			} else {
				log.Println(fmt.Sprintf("FLAKY: %v (%d failures out of %d)", firstFailure, iterations-successes, iterations))
			}
		} else if successes == 0 && firstFailure != nil {
			// Test is 100% failing.
			log.Fatalf("FAIL: %v", firstFailure)
		} else if successes > 0 && firstFailure == nil {
			// Test is 100% succeeding, do nothing.
		} else {
			log.Fatalf("Internal logic error")
		}
	}
}
