// Copyright 2026 The containerd Authors.
// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package shim_test is a test package for the shim. It is intended to be used in conjunction with
// the containerd testing framework.
package shim_test

import (
	"testing"

	task "github.com/containerd/containerd/api/runtime/task/v2"
	"gvisor.dev/gvisor/shim/shimutils"
)

type testCase struct {
	name      string
	shimArgs  map[string]any
	runscArgs map[string]any
}

func TestCreateKillWaitSandbox(t *testing.T) {
	for _, tc := range []testCase{
		{
			name: "default",
		},
		{
			name: "grouping",
			shimArgs: map[string]any{
				"grouping": true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			containerd := shimutils.NewMockContainerd(t, nil, nil)
			spec := shimutils.NewSandboxSpec()

			sandbox, err := shimutils.NewContainer(spec, containerd)
			if err != nil {
				t.Fatalf("failed to create container: %v", err)
			}
			if err := containerd.StartShim(t, sandbox); err != nil {
				t.Fatalf("failed to start shim: %v", err)
			}

			client := containerd.GetClient(t)

			opts, err := containerd.GetRuntimeOptions()
			if err != nil {
				t.Fatalf("failed to get runtime options: %v", err)
			}

			createReq := &task.CreateTaskRequest{
				ID:      sandbox.ID(),
				Bundle:  sandbox.Bundle(),
				Options: opts,
			}

			createResp, err := client.Create(t.Context(), createReq)
			if err != nil {
				t.Fatalf("failed to create task: %v", err)
			}
			if createResp.Pid == 0 {
				t.Errorf("created task PID is 0")
			}

			startReq := &task.StartRequest{
				ID: sandbox.ID(),
			}

			startResp, err := client.Start(t.Context(), startReq)
			if err != nil {
				t.Fatalf("failed to start task: %v", err)
			}
			if startResp.Pid != createResp.Pid {
				t.Errorf("started task PID is different from the created task PID")
			}

			killReq := &task.KillRequest{
				ID:     sandbox.ID(),
				Signal: 9,
				All:    true,
			}

			if _, err := client.Kill(t.Context(), killReq); err != nil {
				t.Fatalf("failed to kill task: %v", err)
			}
		})
	}

}
