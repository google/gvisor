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

package cmd

import (
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/urpc"
)

func TestUser(t *testing.T) {
	testCases := []struct {
		input   string
		want    user
		wantErr bool
	}{
		{input: "0", want: user{kuid: 0, kgid: 0}},
		{input: "7", want: user{kuid: 7, kgid: 0}},
		{input: "49:343", want: user{kuid: 49, kgid: 343}},
		{input: "0:2401", want: user{kuid: 0, kgid: 2401}},
		{input: "", wantErr: true},
		{input: "foo", wantErr: true},
		{input: ":123", wantErr: true},
		{input: "1:2:3", wantErr: true},
	}

	for _, tc := range testCases {
		var u user
		if err := u.Set(tc.input); err != nil && tc.wantErr {
			// We got an error and wanted one.
			continue
		} else if err == nil && tc.wantErr {
			t.Errorf("user.Set(%s): got no error, but wanted one", tc.input)
		} else if err != nil && !tc.wantErr {
			t.Errorf("user.Set(%s): got error %v, but wanted none", tc.input, err)
		} else if u != tc.want {
			t.Errorf("user.Set(%s): got %+v, but wanted %+v", tc.input, u, tc.want)
		}
	}
}

func TestCLIArgs(t *testing.T) {
	testCases := []struct {
		ex       Exec
		argv     []string
		expected control.ExecArgs
	}{
		{
			ex: Exec{
				cwd:         "/foo/bar",
				user:        user{kuid: 0, kgid: 0},
				extraKGIDs:  []string{"1", "2", "3"},
				caps:        []string{"CAP_DAC_OVERRIDE"},
				processPath: "",
			},
			argv: []string{"ls", "/"},
			expected: control.ExecArgs{
				Argv:             []string{"ls", "/"},
				WorkingDirectory: "/foo/bar",
				FilePayload:      urpc.FilePayload{Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}},
				KUID:             0,
				KGID:             0,
				ExtraKGIDs:       []auth.KGID{1, 2, 3},
				Capabilities: &auth.TaskCapabilities{
					BoundingCaps:    auth.CapabilitySetOf(linux.CAP_DAC_OVERRIDE),
					EffectiveCaps:   auth.CapabilitySetOf(linux.CAP_DAC_OVERRIDE),
					InheritableCaps: auth.CapabilitySetOf(linux.CAP_DAC_OVERRIDE),
					PermittedCaps:   auth.CapabilitySetOf(linux.CAP_DAC_OVERRIDE),
				},
			},
		},
	}

	for _, tc := range testCases {
		e, err := tc.ex.argsFromCLI(tc.argv, true)
		if err != nil {
			t.Errorf("argsFromCLI(%+v): got error: %+v", tc.ex, err)
		} else if !cmp.Equal(*e, tc.expected, cmpopts.IgnoreUnexported(os.File{})) {
			t.Errorf("argsFromCLI(%+v): got %+v, but expected %+v", tc.ex, *e, tc.expected)
		}
	}
}

func TestJSONArgs(t *testing.T) {
	testCases := []struct {
		// ex is provided to make sure it is overridden by p.
		ex       Exec
		p        specs.Process
		expected control.ExecArgs
	}{
		{
			ex: Exec{
				cwd:         "/baz/quux",
				user:        user{kuid: 1, kgid: 1},
				extraKGIDs:  []string{"4", "5", "6"},
				caps:        []string{"CAP_SETGID"},
				processPath: "/bin/foo",
			},
			p: specs.Process{
				User: specs.User{UID: 0, GID: 0, AdditionalGids: []uint32{1, 2, 3}},
				Args: []string{"ls", "/"},
				Cwd:  "/foo/bar",
				Capabilities: &specs.LinuxCapabilities{
					Bounding:    []string{"CAP_DAC_OVERRIDE"},
					Effective:   []string{"CAP_DAC_OVERRIDE"},
					Inheritable: []string{"CAP_DAC_OVERRIDE"},
					Permitted:   []string{"CAP_DAC_OVERRIDE"},
				},
			},
			expected: control.ExecArgs{
				Argv:             []string{"ls", "/"},
				WorkingDirectory: "/foo/bar",
				FilePayload:      urpc.FilePayload{Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}},
				KUID:             0,
				KGID:             0,
				ExtraKGIDs:       []auth.KGID{1, 2, 3},
				Capabilities: &auth.TaskCapabilities{
					BoundingCaps:    auth.CapabilitySetOf(linux.CAP_DAC_OVERRIDE),
					EffectiveCaps:   auth.CapabilitySetOf(linux.CAP_DAC_OVERRIDE),
					InheritableCaps: auth.CapabilitySetOf(linux.CAP_DAC_OVERRIDE),
					PermittedCaps:   auth.CapabilitySetOf(linux.CAP_DAC_OVERRIDE),
				},
			},
		},
	}

	for _, tc := range testCases {
		e, err := argsFromProcess(&tc.p, true)
		if err != nil {
			t.Errorf("argsFromProcess(%+v): got error: %+v", tc.p, err)
		} else if !cmp.Equal(*e, tc.expected, cmpopts.IgnoreUnexported(os.File{})) {
			t.Errorf("argsFromProcess(%+v): got %+v, but expected %+v", tc.p, *e, tc.expected)
		}
	}
}
