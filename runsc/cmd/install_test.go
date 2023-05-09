// Copyright 2022 The gVisor Authors.
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

package cmd

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type runtimeDef struct {
	path        string
	runtimeArgs []string
}

func (r *runtimeDef) MarshalJSON() ([]byte, error) {
	args, err := json.Marshal(r.runtimeArgs)
	if err != nil {
		return nil, err
	}
	str := fmt.Sprintf(`{"path": "%s", "runtimeArgs":%s}`, r.path, args)
	return []byte(str), nil
}

func (r *runtimeDef) UnmarshalJSON(data []byte) error {
	var dat map[string]any
	if err := json.Unmarshal(data, &dat); err != nil {
		return err
	}
	if p, ok := dat["path"]; ok {
		r.path = p.(string)
	}
	if p, ok := dat["runtimeArgs"]; ok {
		r.runtimeArgs = p.([]string)
	}
	return nil
}

var defaultInput = map[string]any{
	"runtimes": map[string]*runtimeDef{
		"runtime1": &runtimeDef{
			path:        "runtime1_path",
			runtimeArgs: []string{"some", "args"},
		},
		"other runtime": &runtimeDef{
			path:        "other_runtime_path",
			runtimeArgs: []string{"some", "other", "args"},
		},
		"myRuntime": &runtimeDef{
			path:        "myRuntimePath",
			runtimeArgs: []string{"super", "cool", "args"},
		},
	},
	"exec-opts": []string{"some-cgroup-driver=something", "native.cgroupdriver=init_driver"},
}

func TestInstall(t *testing.T) {

	for _, tc := range []struct {
		name   string
		i      *Install
		input  map[string]any
		output map[string]any
	}{
		{
			name: "clobber",
			i: &Install{
				Runtime:        "myRuntime",
				Experimental:   true,
				Clobber:        true,
				CgroupDriver:   "my_driver",
				executablePath: "some_runsc_path",
				runtimeArgs:    []string{"new", "cool", "args"},
			},
			input: defaultInput,
			output: map[string]any{
				"runtimes": map[string]*runtimeDef{
					"runtime1": &runtimeDef{
						path:        "runtime1_path",
						runtimeArgs: []string{"some", "args"},
					},
					"other runtime": &runtimeDef{
						path:        "other_runtime_path",
						runtimeArgs: []string{"some", "other", "args"},
					},
					"myRuntime": &runtimeDef{
						path:        "some_runsc_path",
						runtimeArgs: []string{"new", "cool", "args"},
					},
				},
				"exec-opts":    []string{"some-cgroup-driver=something", "native.cgroupdriver=my_driver"},
				"experimental": true,
			},
		},
		{
			name: "no clobber",
			i: &Install{
				Runtime:        "myRuntime",
				Experimental:   true,
				Clobber:        false,
				CgroupDriver:   "my_driver",
				executablePath: "some_runsc_path",
				runtimeArgs:    []string{"new", "cool", "args"},
			},
			input: defaultInput,
			output: map[string]any{
				"runtimes": map[string]*runtimeDef{
					"runtime1": &runtimeDef{
						path:        "runtime1_path",
						runtimeArgs: []string{"some", "args"},
					},
					"other runtime": &runtimeDef{
						path:        "other_runtime_path",
						runtimeArgs: []string{"some", "other", "args"},
					},
					"myRuntime": &runtimeDef{
						path:        "myRuntimePath",
						runtimeArgs: []string{"super", "cool", "args"},
					},
				},
				"exec-opts":    []string{"some-cgroup-driver=something", "native.cgroupdriver=init_driver", "native.cgroupdriver=my_driver"},
				"experimental": true,
			},
		},
		{
			name: "new runtime",
			i: &Install{
				Runtime:        "newRuntime",
				Experimental:   true,
				executablePath: "newPath",
				runtimeArgs:    []string{"new", "cool", "args"},
			},
			input: defaultInput,
			output: map[string]any{
				"runtimes": map[string]*runtimeDef{
					"runtime1": &runtimeDef{
						path:        "runtime1_path",
						runtimeArgs: []string{"some", "args"},
					},
					"newRuntime": &runtimeDef{
						path:        "newPath",
						runtimeArgs: []string{"new", "cool", "args"},
					},
					"other runtime": &runtimeDef{
						path:        "other_runtime_path",
						runtimeArgs: []string{"some", "other", "args"},
					},
					"myRuntime": &runtimeDef{
						path:        "myRuntimePath",
						runtimeArgs: []string{"super", "cool", "args"},
					},
				},
				"exec-opts":    []string{"some-cgroup-driver=something", "native.cgroupdriver=init_driver"},
				"experimental": true,
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {

			mockRead := func(_ string) ([]byte, error) {
				return json.MarshalIndent(tc.input, "", "  ")
			}

			got := []byte{}
			mockWrite := func(c map[string]any, _ string) error {
				res, err := json.MarshalIndent(c, "", "  ")
				if err != nil {
					return err
				}
				got = res
				return nil
			}

			rw := configReaderWriter{
				read:  mockRead,
				write: mockWrite,
			}

			if err := doInstallConfig(tc.i, rw); err != nil {
				t.Fatalf("Error updating config: %v", err)
			}

			want, err := json.MarshalIndent(tc.output, "", "  ")
			if err != nil {
				t.Fatalf("Failed to marshal output: %v", err)
			}

			if res := cmp.Diff(string(want), string(got)); res != "" {
				t.Fatalf("Mismatch output (-want +got): %s", res)
			}
		})
	}
}

func TestUninstall(t *testing.T) {
	for _, tc := range []struct {
		name    string
		u       *Uninstall
		input   map[string]any
		output  map[string]any
		wantErr bool
	}{
		{
			name: "runtime found",
			u: &Uninstall{
				Runtime: "other runtime",
			},
			input: defaultInput,
			output: map[string]any{
				"runtimes": map[string]*runtimeDef{
					"runtime1": &runtimeDef{
						path:        "runtime1_path",
						runtimeArgs: []string{"some", "args"},
					},
					"myRuntime": &runtimeDef{
						path:        "myRuntimePath",
						runtimeArgs: []string{"super", "cool", "args"},
					},
				},
				"exec-opts": []string{"some-cgroup-driver=something", "native.cgroupdriver=init_driver"},
			},
		},
		{
			name: "runtime not found",
			u: &Uninstall{
				Runtime: "not found runtime",
			},
			input:   defaultInput,
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockRead := func(_ string) ([]byte, error) {
				return json.MarshalIndent(tc.input, "", "  ")
			}

			got := []byte{}
			mockWrite := func(c map[string]any, _ string) error {
				res, err := json.MarshalIndent(c, "", "  ")
				if err != nil {
					return err
				}
				got = res
				return nil
			}

			rw := configReaderWriter{
				read:  mockRead,
				write: mockWrite,
			}

			err := doUninstallConfig(tc.u, rw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Did not get an error when expected.")
				}
				return
			}
			if err != nil {
				t.Fatalf("Error updating config: %v", err)
			}

			want, err := json.MarshalIndent(tc.output, "", "  ")
			if err != nil {
				t.Fatalf("Failed to marshal output: %v", err)
			}
			if res := cmp.Diff(string(want), string(got)); res != "" {
				t.Fatalf("Mismatch output (-want +got-): %s", res)
			}
		})
	}
}
