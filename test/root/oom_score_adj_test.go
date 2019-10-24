// Copyright 2018 The gVisor Authors.
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

package root

import (
	"fmt"
	"os"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/specutils"
	"gvisor.dev/gvisor/runsc/testutil"
)

var (
	maxOOMScoreAdj  = 1000
	highOOMScoreAdj = 500
	lowOOMScoreAdj  = -500
	minOOMScoreAdj  = -1000
)

// Tests for oom_score_adj have to be run as root (rather than in a user
// namespace) because we need to adjust oom_score_adj for PIDs other than our
// own and test values below 0.

// TestOOMScoreAdjSingle tests that oom_score_adj is set properly in a
// single container sandbox.
func TestOOMScoreAdjSingle(t *testing.T) {
	rootDir, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer os.RemoveAll(rootDir)

	conf := testutil.TestConfig()
	conf.RootDir = rootDir

	ppid, err := specutils.GetParentPid(os.Getpid())
	if err != nil {
		t.Fatalf("getting parent pid: %v", err)
	}
	parentOOMScoreAdj, err := specutils.GetOOMScoreAdj(ppid)
	if err != nil {
		t.Fatalf("getting parent oom_score_adj: %v", err)
	}

	testCases := []struct {
		Name string

		// OOMScoreAdj is the oom_score_adj set to the OCI spec. If nil then
		// no value is set.
		OOMScoreAdj *int
	}{
		{
			Name:        "max",
			OOMScoreAdj: &maxOOMScoreAdj,
		},
		{
			Name:        "high",
			OOMScoreAdj: &highOOMScoreAdj,
		},
		{
			Name:        "low",
			OOMScoreAdj: &lowOOMScoreAdj,
		},
		{
			Name:        "min",
			OOMScoreAdj: &minOOMScoreAdj,
		},
		{
			Name:        "nil",
			OOMScoreAdj: &parentOOMScoreAdj,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			id := testutil.UniqueContainerID()
			s := testutil.NewSpecWithArgs("sleep", "1000")
			s.Process.OOMScoreAdj = testCase.OOMScoreAdj

			containers, cleanup, err := startContainers(conf, []*specs.Spec{s}, []string{id})
			if err != nil {
				t.Fatalf("error starting containers: %v", err)
			}
			defer cleanup()

			c := containers[0]

			// Verify the gofer's oom_score_adj
			if testCase.OOMScoreAdj != nil {
				goferScore, err := specutils.GetOOMScoreAdj(c.GoferPid)
				if err != nil {
					t.Fatalf("error reading gofer oom_score_adj: %v", err)
				}
				if goferScore != *testCase.OOMScoreAdj {
					t.Errorf("gofer oom_score_adj got: %d, want: %d", goferScore, *testCase.OOMScoreAdj)
				}

				// Verify the sandbox's oom_score_adj.
				//
				// The sandbox should be the same for all containers so just use
				// the first one.
				sandboxPid := c.Sandbox.Pid
				sandboxScore, err := specutils.GetOOMScoreAdj(sandboxPid)
				if err != nil {
					t.Fatalf("error reading sandbox oom_score_adj: %v", err)
				}
				if sandboxScore != *testCase.OOMScoreAdj {
					t.Errorf("sandbox oom_score_adj got: %d, want: %d", sandboxScore, *testCase.OOMScoreAdj)
				}
			}
		})
	}
}

// TestOOMScoreAdjMulti tests that oom_score_adj is set properly in a
// multi-container sandbox.
func TestOOMScoreAdjMulti(t *testing.T) {
	rootDir, err := testutil.SetupRootDir()
	if err != nil {
		t.Fatalf("error creating root dir: %v", err)
	}
	defer os.RemoveAll(rootDir)

	conf := testutil.TestConfig()
	conf.RootDir = rootDir

	ppid, err := specutils.GetParentPid(os.Getpid())
	if err != nil {
		t.Fatalf("getting parent pid: %v", err)
	}
	parentOOMScoreAdj, err := specutils.GetOOMScoreAdj(ppid)
	if err != nil {
		t.Fatalf("getting parent oom_score_adj: %v", err)
	}

	testCases := []struct {
		Name string

		// OOMScoreAdj is the oom_score_adj set to the OCI spec. If nil then
		// no value is set. One value for each container. The first value is the
		// root container.
		OOMScoreAdj []*int

		// Expected is the expected oom_score_adj of the sandbox. If nil, then
		// this value is ignored.
		Expected *int

		// Remove is a set of container indexes to remove from the sandbox.
		Remove []int

		// ExpectedAfterRemove is the expected oom_score_adj of the sandbox
		// after containers are removed. Ignored if nil.
		ExpectedAfterRemove *int
	}{
		// A single container CRI test case. This should not happen in
		// practice as there should be at least one container besides the pause
		// container. However, we include a test case to ensure sane behavior.
		{
			Name:        "single",
			OOMScoreAdj: []*int{&highOOMScoreAdj},
			Expected:    &parentOOMScoreAdj,
		},
		{
			Name:        "multi_no_value",
			OOMScoreAdj: []*int{nil, nil, nil},
			Expected:    &parentOOMScoreAdj,
		},
		{
			Name:        "multi_non_nil_root",
			OOMScoreAdj: []*int{&minOOMScoreAdj, nil, nil},
			Expected:    &parentOOMScoreAdj,
		},
		{
			Name:        "multi_value",
			OOMScoreAdj: []*int{&minOOMScoreAdj, &highOOMScoreAdj, &lowOOMScoreAdj},
			// The lowest value excluding the root container is expected.
			Expected: &lowOOMScoreAdj,
		},
		{
			Name:        "multi_min_value",
			OOMScoreAdj: []*int{&minOOMScoreAdj, &lowOOMScoreAdj},
			// The lowest value excluding the root container is expected.
			Expected: &lowOOMScoreAdj,
		},
		{
			Name:        "multi_max_value",
			OOMScoreAdj: []*int{&minOOMScoreAdj, &maxOOMScoreAdj, &highOOMScoreAdj},
			// The lowest value excluding the root container is expected.
			Expected: &highOOMScoreAdj,
		},
		{
			Name:        "remove_adjusted",
			OOMScoreAdj: []*int{&minOOMScoreAdj, &maxOOMScoreAdj, &highOOMScoreAdj},
			// The lowest value excluding the root container is expected.
			Expected: &highOOMScoreAdj,
			// Remove highOOMScoreAdj container.
			Remove:              []int{2},
			ExpectedAfterRemove: &maxOOMScoreAdj,
		},
		{
			// This test removes all non-root sandboxes with a specified oomScoreAdj.
			Name:        "remove_to_nil",
			OOMScoreAdj: []*int{&minOOMScoreAdj, nil, &lowOOMScoreAdj},
			Expected:    &lowOOMScoreAdj,
			// Remove lowOOMScoreAdj container.
			Remove: []int{2},
			// The oom_score_adj expected after remove is that of the parent process.
			ExpectedAfterRemove: &parentOOMScoreAdj,
		},
		{
			Name:        "remove_no_effect",
			OOMScoreAdj: []*int{&minOOMScoreAdj, &maxOOMScoreAdj, &highOOMScoreAdj},
			// The lowest value excluding the root container is expected.
			Expected: &highOOMScoreAdj,
			// Remove the maxOOMScoreAdj container.
			Remove:              []int{1},
			ExpectedAfterRemove: &highOOMScoreAdj,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.Name, func(t *testing.T) {
			var cmds [][]string
			var oomScoreAdj []*int
			var toRemove []string

			for _, oomScore := range testCase.OOMScoreAdj {
				oomScoreAdj = append(oomScoreAdj, oomScore)
				cmds = append(cmds, []string{"sleep", "100"})
			}

			specs, ids := createSpecs(cmds...)
			for i, spec := range specs {
				// Ensure the correct value is set, including no value.
				spec.Process.OOMScoreAdj = oomScoreAdj[i]

				for _, j := range testCase.Remove {
					if i == j {
						toRemove = append(toRemove, ids[i])
					}
				}
			}

			containers, cleanup, err := startContainers(conf, specs, ids)
			if err != nil {
				t.Fatalf("error starting containers: %v", err)
			}
			defer cleanup()

			for i, c := range containers {
				if oomScoreAdj[i] != nil {
					// Verify the gofer's oom_score_adj
					score, err := specutils.GetOOMScoreAdj(c.GoferPid)
					if err != nil {
						t.Fatalf("error reading gofer oom_score_adj: %v", err)
					}
					if score != *oomScoreAdj[i] {
						t.Errorf("gofer oom_score_adj got: %d, want: %d", score, *oomScoreAdj[i])
					}
				}
			}

			// Verify the sandbox's oom_score_adj.
			//
			// The sandbox should be the same for all containers so just use
			// the first one.
			sandboxPid := containers[0].Sandbox.Pid
			if testCase.Expected != nil {
				score, err := specutils.GetOOMScoreAdj(sandboxPid)
				if err != nil {
					t.Fatalf("error reading sandbox oom_score_adj: %v", err)
				}
				if score != *testCase.Expected {
					t.Errorf("sandbox oom_score_adj got: %d, want: %d", score, *testCase.Expected)
				}
			}

			if len(toRemove) == 0 {
				return
			}

			// Remove containers.
			for _, removeID := range toRemove {
				for _, c := range containers {
					if c.ID == removeID {
						c.Destroy()
					}
				}
			}

			// Check the new adjusted oom_score_adj.
			if testCase.ExpectedAfterRemove != nil {
				scoreAfterRemove, err := specutils.GetOOMScoreAdj(sandboxPid)
				if err != nil {
					t.Fatalf("error reading sandbox oom_score_adj: %v", err)
				}
				if scoreAfterRemove != *testCase.ExpectedAfterRemove {
					t.Errorf("sandbox oom_score_adj got: %d, want: %d", scoreAfterRemove, *testCase.ExpectedAfterRemove)
				}
			}
		})
	}
}

func createSpecs(cmds ...[]string) ([]*specs.Spec, []string) {
	var specs []*specs.Spec
	var ids []string
	rootID := testutil.UniqueContainerID()

	for i, cmd := range cmds {
		spec := testutil.NewSpecWithArgs(cmd...)
		if i == 0 {
			spec.Annotations = map[string]string{
				specutils.ContainerdContainerTypeAnnotation: specutils.ContainerdContainerTypeSandbox,
			}
			ids = append(ids, rootID)
		} else {
			spec.Annotations = map[string]string{
				specutils.ContainerdContainerTypeAnnotation: specutils.ContainerdContainerTypeContainer,
				specutils.ContainerdSandboxIDAnnotation:     rootID,
			}
			ids = append(ids, testutil.UniqueContainerID())
		}
		specs = append(specs, spec)
	}
	return specs, ids
}

func startContainers(conf *boot.Config, specs []*specs.Spec, ids []string) ([]*container.Container, func(), error) {
	if len(conf.RootDir) == 0 {
		panic("conf.RootDir not set. Call testutil.SetupRootDir() to set.")
	}

	var containers []*container.Container
	var bundles []string
	cleanup := func() {
		for _, c := range containers {
			c.Destroy()
		}
		for _, b := range bundles {
			os.RemoveAll(b)
		}
	}
	for i, spec := range specs {
		bundleDir, err := testutil.SetupBundleDir(spec)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("error setting up container: %v", err)
		}
		bundles = append(bundles, bundleDir)

		args := container.Args{
			ID:        ids[i],
			Spec:      spec,
			BundleDir: bundleDir,
		}
		cont, err := container.New(conf, args)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("error creating container: %v", err)
		}
		containers = append(containers, cont)

		if err := cont.Start(conf); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("error starting container: %v", err)
		}
	}
	return containers, cleanup, nil
}
