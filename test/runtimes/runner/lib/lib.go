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

// Package lib provides utilities for runner.
package lib

import (
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// ProctorSettings contains settings passed directly to the proctor process.
type ProctorSettings struct {
	// PerTestTimeout is the timeout for each individual test.
	PerTestTimeout time.Duration
	// RunsPerTest is the number of times to run each test.
	// A value of 0 is the same as a value of 1, i.e. "run once".
	RunsPerTest int
	// If FlakyIsError is true, a flaky test will be considered as a failure.
	// If it is false, a flaky test will be considered as passing.
	FlakyIsError bool
	// If FlakyShortCircuit is true, when runnins with RunsPerTest > 1 and a test is detected as
	// flaky, exit immediately rather than running for all RunsPerTest attempts.
	FlakyShortCircuit bool
}

// ToArgs converts these settings to command-line arguments to pass to the proctor binary.
func (p ProctorSettings) ToArgs() []string {
	return []string{
		fmt.Sprintf("--per_test_timeout=%v", p.PerTestTimeout),
		fmt.Sprintf("--runs_per_test=%d", p.RunsPerTest),
		fmt.Sprintf("--flaky_is_error=%v", p.FlakyIsError),
		fmt.Sprintf("--flaky_short_circuit=%v", p.FlakyShortCircuit),
	}
}

// Filter is a predicate function for filtering tests.
// It returns true if the given test name should be run.
type Filter func(test string) bool

// RunTests is a helper that is called by main. It exists so that we can run
// defered functions before exiting. It returns an exit code that should be
// passed to os.Exit.
func RunTests(lang, image string, filter Filter, batchSize int, timeout time.Duration, proctorSettings ProctorSettings) int {
	// Construct the shared docker instance.
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, testutil.DefaultLogger(lang))
	defer d.CleanUp(ctx)

	if err := testutil.TouchShardStatusFile(); err != nil {
		fmt.Fprintf(os.Stderr, "error touching status shard file: %v\n", err)
		return 1
	}

	timeoutChan := make(chan struct{})
	// Add one minute to let proctor handle timeout.
	timer := time.AfterFunc(timeout+time.Minute, func() { close(timeoutChan) })
	defer timer.Stop()
	// Get a slice of tests to run. This will also start a single Docker
	// container that will be used to run each test. The final test will
	// stop the Docker container.
	tests, err := getTests(ctx, d, lang, image, batchSize, timeoutChan, timeout, filter, proctorSettings)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return 1
	}
	m := mainStart(tests)
	return m.Run()
}

// getTests executes all tests as table tests.
func getTests(ctx context.Context, d *dockerutil.Container, lang, image string, batchSize int, timeoutChan chan struct{}, timeout time.Duration, filter Filter, proctorSettings ProctorSettings) ([]testing.InternalTest, error) {
	startTime := time.Now()

	// Start the container.
	opts := dockerutil.RunOpts{
		Image: fmt.Sprintf("runtimes/%s", image),
	}
	d.CopyFiles(&opts, "/proctor", "test/runtimes/proctor/proctor")
	if err := d.Spawn(ctx, opts, "/proctor/proctor", "--pause"); err != nil {
		return nil, fmt.Errorf("docker run failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-done:
			return
		// Make sure that the useful load takes 2/3 of timeout.
		case <-time.After((timeout - time.Since(startTime)) / 3):
		case <-timeoutChan:
		}
		panic("TIMEOUT: Unable to get a list of tests")
	}()
	// Get a list of all tests in the image.
	list, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/proctor/proctor", "--runtime", lang, "--list")
	if err != nil {
		return nil, fmt.Errorf("docker exec failed: %v", err)
	}
	close(done)

	// Calculate a subset of tests.
	tests := strings.Fields(list)
	sort.Strings(tests)
	indices, err := testutil.TestIndicesForShard(len(tests))
	if err != nil {
		return nil, fmt.Errorf("TestsForShard() failed: %v", err)
	}
	indicesMap := make(map[int]struct{}, len(indices))
	for _, i := range indices {
		indicesMap[i] = struct{}{}
	}
	var testsNotInShard []string
	for i, tc := range tests {
		if _, found := indicesMap[i]; !found {
			testsNotInShard = append(testsNotInShard, tc)
		}
	}
	if len(testsNotInShard) > 0 {
		log.Infof("Tests not in this shard: %s", strings.Join(testsNotInShard, ","))
	}

	var itests []testing.InternalTest
	for i := 0; i < len(indices); i += batchSize {
		var tcs []string
		end := i + batchSize
		if end > len(indices) {
			end = len(indices)
		}
		for _, tc := range indices[i:end] {
			// Add test if not filtered.
			if filter != nil && !filter(tests[tc]) {
				log.Infof("Skipping test case %s\n", tests[tc])
				continue
			}
			tcs = append(tcs, tests[tc])
		}
		if len(tcs) == 0 {
			// No tests to add to this batch.
			continue
		}
		itests = append(itests, testing.InternalTest{
			Name: strings.Join(tcs, ", "),
			F: func(t *testing.T) {
				var (
					now    = time.Now()
					done   = make(chan struct{})
					output string
					err    error
				)

				state, err := d.Status(ctx)
				if err != nil {
					t.Fatalf("Could not find container status: %v", err)
				}
				if !state.Running {
					t.Fatalf("container is not running: state = %s", state.Status)
				}
				log.Infof("Running test case batch: %s", strings.Join(tcs, ","))

				go func() {
					argv := []string{
						"/proctor/proctor", "--runtime", lang,
						"--tests", strings.Join(tcs, ","),
						fmt.Sprintf("--timeout=%s", timeout-time.Since(startTime)),
					}
					argv = append(argv, proctorSettings.ToArgs()...)
					output, err = d.Exec(ctx, dockerutil.ExecOpts{}, argv...)
					close(done)
				}()

				select {
				case <-done:
					if err == nil {
						fmt.Printf("PASS: (%v) %d tests passed\n", time.Since(now), len(tcs))
						return
					}
					t.Fatalf("FAIL: (%v):\nBatch:\n%s\nOutput:\n%s\n", time.Since(now), strings.Join(tcs, "\n"), output)
				// Add one minute to let proctor handle timeout.
				case <-timeoutChan:
					t.Fatalf("TIMEOUT: (%v):\nBatch:\n%s\nOutput:\n%s\n", time.Since(now), strings.Join(tcs, "\n"), output)
				}
			},
		})
	}

	return itests, nil
}

// ExcludeFilter reads the exclude file and returns a filter that excludes the tests listed in
// the given CSV file.
func ExcludeFilter(excludeFile string) (Filter, error) {
	excludes := make(map[string]struct{})
	if excludeFile == "" {
		return nil, nil
	}
	f, err := os.Open(excludeFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	r := csv.NewReader(f)

	// First line is header. Skip it.
	if _, err := r.Read(); err != nil {
		return nil, err
	}

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		excludes[record[0]] = struct{}{}
	}
	return func(test string) bool {
		_, found := excludes[test]
		return !found
	}, nil
}

// testDeps implements testing.testDeps (an unexported interface), and is
// required to use testing.MainStart.
type testDeps struct{}

func (f testDeps) MatchString(a, b string) (bool, error)       { return a == b, nil }
func (f testDeps) StartCPUProfile(io.Writer) error             { return nil }
func (f testDeps) StopCPUProfile()                             {}
func (f testDeps) WriteProfileTo(string, io.Writer, int) error { return nil }
func (f testDeps) ImportPath() string                          { return "" }
func (f testDeps) StartTestLog(io.Writer)                      {}
func (f testDeps) StopTestLog() error                          { return nil }
func (f testDeps) SetPanicOnExit0(bool)                        {}
func (f testDeps) CoordinateFuzzing(time.Duration, int64, time.Duration, int64, int, []corpusEntry, []reflect.Type, string, string) error {
	return nil
}
func (f testDeps) RunFuzzWorker(func(corpusEntry) error) error              { return nil }
func (f testDeps) ReadCorpus(string, []reflect.Type) ([]corpusEntry, error) { return nil, nil }
func (f testDeps) CheckCorpus([]any, []reflect.Type) error                  { return nil }
func (f testDeps) ResetCoverage()                                           {}
func (f testDeps) SnapshotCoverage()                                        {}

// Copied from testing/fuzz.go.
type corpusEntry = struct {
	Parent     string
	Path       string
	Data       []byte
	Values     []any
	Generation int
	IsSeed     bool
}
