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
	m := mainStart(tests)
	return m.Run()
}

func dockerHeartbeat(ctx context.Context, d *dockerutil.Container) chan struct{} {
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(30 * time.Second):
				out, err := d.Exec(ctx, dockerutil.ExecOpts{}, "ps", "axf")
				log.Infof("runner checking in: %s\n%s", err, out)
			}
		}
	}()

	return done
}

// getTests executes all tests as table tests.
func getTests(ctx context.Context, d *dockerutil.Container, lang, image string, batchSize int, timeout time.Duration, excludes map[string]struct{}) ([]testing.InternalTest, error) {
	hdone := dockerHeartbeat(ctx, d)
	defer close(hdone)
	// Start the container.
	opts := dockerutil.RunOpts{
		Image: fmt.Sprintf("runtimes/%s", image),
	}
	log.Infof("Copy proctor")
	d.CopyFiles(&opts, "/proctor", "test/runtimes/proctor/proctor")
	if err := d.Spawn(ctx, opts, "/proctor/proctor", "--pause"); err != nil {
		return nil, fmt.Errorf("docker run failed: %v", err)
	}

	log.Infof("List tests")
	// Get a list of all tests in the image.
	list, err := d.Exec(ctx, dockerutil.ExecOpts{}, "/proctor/proctor", "--runtime", lang, "--list")
	if err != nil {
		return nil, fmt.Errorf("docker exec failed: %v", err)
	}
	log.Infof("All tests: %s", list)

	// Calculate a subset of tests.
	tests := strings.Fields(list)
	sort.Strings(tests)
	indices, err := testutil.TestIndicesForShard(len(tests))
	if err != nil {
		return nil, fmt.Errorf("TestsForShard() failed: %v", err)
	}
	log.Infof("indices: %s", indices)

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
		log.Infof("Tests: %s", tcs)
		itests = append(itests, testing.InternalTest{
			Name: strings.Join(tcs, ", "),
			F: func(t *testing.T) {
				var (
					now    = time.Now()
					done   = make(chan struct{})
					output string
					err    error
				)
				log.Infof("Run: %s", strings.Join(tcs, ", "))

				hdone := dockerHeartbeat(ctx, d)
				defer close(hdone)

				log.Infof("Get status")
				state, err := d.Status(ctx)
				if err != nil {
					t.Fatalf("Could not find container status: %v", err)
				}
				log.Infof("Get status: %s %s", err, state)
				if !state.Running {
					t.Fatalf("container is not running: state = %s", state.Status)
				}

				go func() {
					log.Infof("Run tests: %s", strings.Join(tcs, ","))
					output, err = d.Exec(ctx, dockerutil.ExecOpts{}, "/proctor/proctor", "--runtime", lang, "--tests", strings.Join(tcs, ","), fmt.Sprintf("--timeout=%s", timeout))
					log.Infof("proctor exited: %s", err)
					close(done)
				}()

				select {
				case <-done:
					log.Infof("Handle test results")
					if err == nil {
						fmt.Printf("PASS: (%v) %d tests passed\n", time.Since(now), len(tcs))
						return
					}
					t.Fatalf("FAIL: (%v):\nBatch:\n%s\nOutput:\n%s\n", time.Since(now), strings.Join(tcs, "\n"), output)
				// Add one minute to let proctor handle timeout.
				case <-time.After(timeout + time.Minute):
					log.Infof("timed out: \n%s", log.Stacks(true))
					go func() {
						time.Sleep(30 * time.Second)
						log.Warningf("timed out!!!")
						go func() {
							panic("timed out!!!")
						}()
						time.Sleep(5 * time.Second)
						os.Exit(5)
					}()
					t.Fatalf("TIMEOUT: (%v):\nBatch:\n%s\nOutput:\n%s\n", time.Since(now), strings.Join(tcs, "\n"), output)
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
func (f testDeps) CoordinateFuzzing(time.Duration, int64, time.Duration, int64, int, []corpusEntry, []reflect.Type, string, string) error {
	return nil
}
func (f testDeps) RunFuzzWorker(func(corpusEntry) error) error              { return nil }
func (f testDeps) ReadCorpus(string, []reflect.Type) ([]corpusEntry, error) { return nil, nil }
func (f testDeps) CheckCorpus([]interface{}, []reflect.Type) error          { return nil }
func (f testDeps) ResetCoverage()                                           {}
func (f testDeps) SnapshotCoverage()                                        {}

// Copied from testing/fuzz.go.
type corpusEntry = struct {
	Parent     string
	Path       string
	Data       []byte
	Values     []interface{}
	Generation int
	IsSeed     bool
}
