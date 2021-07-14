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
	"sort"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

// RunTests is a helper that is called by main. It exists so that we can run
// defered functions before exiting. It returns an exit code that should be
// passed to os.Exit.
func RunTests(lang, image, excludeFile string, batchSize int, timeout time.Duration) int {
	// TODO(gvisor.dev/issue/1624): Remove those tests from all exclude lists
	// that only fail with VFS1.

	// Get tests to exclude.
	excludes, err := getExcludes(excludeFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting exclude list: %s\n", err.Error())
		return 1
	}

	// Construct the shared docker instance.
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, testutil.DefaultLogger(lang))
	defer d.CleanUp(ctx)

	if err := testutil.TouchShardStatusFile(); err != nil {
		fmt.Fprintf(os.Stderr, "error touching status shard file: %v\n", err)
		return 1
	}

	// Get a slice of tests to run. This will also start a single Docker
	// container that will be used to run each test. The final test will
	// stop the Docker container.
	tests, err := getTests(ctx, d, lang, image, batchSize, timeout, excludes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		return 1
	}

	m := testing.MainStart(testDeps{}, tests, nil, nil)
	return m.Run()
}

// getTests executes all tests as table tests.
func getTests(ctx context.Context, d *dockerutil.Container, lang, image string, batchSize int, timeout time.Duration, excludes map[string]struct{}) ([]testing.InternalTest, error) {
	// Start the container.
	opts := dockerutil.RunOpts{
		Image: fmt.Sprintf("runtimes/%s", image),
	}
	d.CopyFiles(&opts, "/proctor", "test/runtimes/proctor/proctor")
	if err := d.Spawn(ctx, opts, "/proctor/proctor", "--pause"); err != nil {
		return nil, fmt.Errorf("docker run failed: %v", err)
	}

	// Get a list of all tests in the image.
	list, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/proctor/proctor", "--runtime", lang, "--list")
	if err != nil {
		return nil, fmt.Errorf("docker exec failed: %v", err)
	}

	// Calculate a subset of tests.
	tests := strings.Fields(list)
	sort.Strings(tests)
	indices, err := testutil.TestIndicesForShard(len(tests))
	if err != nil {
		return nil, fmt.Errorf("TestsForShard() failed: %v", err)
	}

	var itests []testing.InternalTest
	for i := 0; i < len(indices); i += batchSize {
		var tcs []string
		end := i + batchSize
		if end > len(indices) {
			end = len(indices)
		}
		for _, tc := range indices[i:end] {
			// Add test if not excluded.
			if _, ok := excludes[tests[tc]]; ok {
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

				go func() {
					output, err = d.Exec(ctx, dockerutil.ExecOpts{}, "/proctor/proctor", "--runtime", lang, "--tests", strings.Join(tcs, ","))
					close(done)
				}()

				select {
				case <-done:
					if err == nil {
						fmt.Printf("PASS: (%v) %d tests passed\n", time.Since(now), len(tcs))
						return
					}
					t.Errorf("FAIL: (%v):\nBatch:\n%s\nOutput:\n%s\n", time.Since(now), strings.Join(tcs, "\n"), output)
				case <-time.After(timeout):
					t.Errorf("TIMEOUT: (%v):\nBatch:\n%s\nOutput:\n%s\n", time.Since(now), strings.Join(tcs, "\n"), output)
				}
			},
		})
	}

	return itests, nil
}

// getExcludes reads the exclude file and returns a set of test names to
// exclude.
func getExcludes(excludeFile string) (map[string]struct{}, error) {
	excludes := make(map[string]struct{})
	if excludeFile == "" {
		return excludes, nil
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
	return excludes, nil
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
