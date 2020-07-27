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
	"os"
	"path/filepath"
	"testing"
	"time"
)

type testCase struct {
	name          string
	pprof         Pprof
	expectedFiles []string
}

func TestPprof(t *testing.T) {
	// Basepath and expected file names for each type of profile.
	basePath := "/tmp/test/profile"
	block := "block.pprof"
	cpu := "cpu.pprof"
	goprofle := "go.pprof"
	heap := "heap.pprof"
	mutex := "mutex.pprof"

	testCases := []testCase{
		{
			name: "Cpu",
			pprof: Pprof{
				BasePath:   basePath,
				CPUProfile: true,
				Duration:   2 * time.Second,
			},
			expectedFiles: []string{cpu},
		},
		{
			name: "All",
			pprof: Pprof{
				BasePath:         basePath,
				BlockProfile:     true,
				CPUProfile:       true,
				GoRoutineProfile: true,
				HeapProfile:      true,
				MutexProfile:     true,
				Duration:         2 * time.Second,
			},
			expectedFiles: []string{block, cpu, goprofle, heap, mutex},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := MakeContainer(ctx, t)
			// Set basepath to include the container name so there are no conflicts.
			tc.pprof.BasePath = filepath.Join(tc.pprof.BasePath, c.Name)
			c.AddProfile(&tc.pprof)

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
				for start := time.Now(); time.Since(start) < tc.pprof.Duration; time.Sleep(500 * time.Millisecond) {
					if err := checkFiles(tc); err == nil {
						break
					}
				}
			}()

			// Check all expected files exist and have data.
			if err := checkFiles(tc); err != nil {
				t.Fatalf(err.Error())
			}
		})
	}
}

func checkFiles(tc testCase) error {
	for _, file := range tc.expectedFiles {
		stat, err := os.Stat(filepath.Join(tc.pprof.BasePath, file))
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
