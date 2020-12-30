// Copyright 2020 The gVisor Authors.
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

package dockerutil

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testCase struct {
	name          string
	profile       profile
	expectedFiles []string
}

func TestProfile(t *testing.T) {
	// Basepath and expected file names for each type of profile.
	tmpDir, err := ioutil.TempDir("", "")
	if err != nil {
		t.Fatalf("unable to create temporary directory: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// All expected names.
	basePath := tmpDir
	block := "block.pprof"
	cpu := "cpu.pprof"
	heap := "heap.pprof"
	mutex := "mutex.pprof"

	testCases := []testCase{
		{
			name: "One",
			profile: profile{
				BasePath: basePath,
				Types:    []string{"cpu"},
				Duration: 2 * time.Second,
			},
			expectedFiles: []string{cpu},
		},
		{
			name: "All",
			profile: profile{
				BasePath: basePath,
				Types:    []string{"block", "cpu", "heap", "mutex"},
				Duration: 2 * time.Second,
			},
			expectedFiles: []string{block, cpu, heap, mutex},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := MakeContainer(ctx, t)

			// Set basepath to include the container name so there are no conflicts.
			localProfile := tc.profile // Copy it.
			localProfile.BasePath = filepath.Join(localProfile.BasePath, tc.name)

			// Set directly on the container, to avoid flags.
			c.profile = &localProfile

			func() {
				defer c.CleanUp(ctx)

				// Start a container.
				if err := c.Spawn(ctx, RunOpts{
					Image: "basic/alpine",
				}, "sleep", "1000"); err != nil {
					t.Fatalf("run failed with: %v", err)
				}

				if status, err := c.Status(context.Background()); !status.Running {
					t.Fatalf("container is not yet running: %+v err: %v", status, err)
				}

				// End early if the expected files exist and have data.
				for start := time.Now(); time.Since(start) < localProfile.Duration; time.Sleep(100 * time.Millisecond) {
					if err := checkFiles(localProfile.BasePath, tc.expectedFiles); err == nil {
						break
					}
				}
			}()

			// Check all expected files exist and have data.
			if err := checkFiles(localProfile.BasePath, tc.expectedFiles); err != nil {
				t.Fatalf(err.Error())
			}
		})
	}
}

func checkFiles(basePath string, expectedFiles []string) error {
	for _, file := range expectedFiles {
		stat, err := os.Stat(filepath.Join(basePath, file))
		if err != nil {
			return fmt.Errorf("stat failed with: %v", err)
		} else if stat.Size() < 1 {
			return fmt.Errorf("file not written to: %+v", stat)
		}
	}
	return nil
}

func TestMain(m *testing.M) {
	EnsureSupportedDockerVersion()
	os.Exit(m.Run())
}
