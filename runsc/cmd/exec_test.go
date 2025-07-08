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
)

func TestUser(t *testing.T) {
	testCases := []struct {
		input   string
		want    user
		wantErr bool
	}{
		{input: "0", want: user{kuid: 0, kuidSet: true, kgid: 0, kgidSet: false}},
		{input: "7", want: user{kuid: 7, kuidSet: true, kgid: 0, kgidSet: false}},
		{input: "49:343", want: user{kuid: 49, kuidSet: true, kgid: 343, kgidSet: true}},
		{input: "0:2401", want: user{kuid: 0, kuidSet: true, kgid: 2401, kgidSet: true}},
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
		name     string
		ex       Exec
		spec     specs.Process
		argv     []string
		expected control.ExecArgs
	}{
		{
			name: "spec used by default",
			ex:   Exec{},
			spec: specs.Process{
				User:         specs.User{UID: 2, GID: 2, AdditionalGids: []uint32{1, 2, 3}},
				Capabilities: &specs.LinuxCapabilities{Bounding: []string{"CAP_DAC_OVERRIDE"}, Inheritable: []string{"CAP_DAC_OVERRIDE"}},
				Cwd:          "/foo/bar",
				Env:          []string{"FOO=bar"},
			},
			argv: []string{"ls", "/"},
			expected: control.ExecArgs{
				Argv:             []string{"ls", "/"},
				Envv:             []string{"FOO=bar"},
				WorkingDirectory: "/foo/bar",
				KUID:             2,
				KGID:             2,
				ExtraKGIDs:       []auth.KGID{1, 2, 3},
				Capabilities: &auth.TaskCapabilities{
					BoundingCaps:    auth.CapabilitySetOf(linux.CAP_DAC_OVERRIDE),
					InheritableCaps: auth.CapabilitySetOf(linux.CAP_DAC_OVERRIDE),
				},
			},
		},
		{
			name: "spec overridden by CLI",
			ex: Exec{
				cwd:        "/baz",
				user:       user{kuid: 4, kuidSet: true, kgid: 4, kgidSet: true},
				extraKGIDs: []string{"4", "5", "6"},
				caps:       []string{"CAP_DAC_READ_SEARCH"},
				env:        []string{"BAZ=new", "XYZ=xyz,BAZ=new"},
			},
			spec: specs.Process{
				User:         specs.User{UID: 2, GID: 2, AdditionalGids: []uint32{1, 2, 3}},
				Capabilities: &specs.LinuxCapabilities{Bounding: []string{"CAP_DAC_OVERRIDE"}, Inheritable: []string{"CAP_DAC_OVERRIDE"}},
				Cwd:          "/foo/bar",
				Env:          []string{"FOO=bar"},
			},
			argv: []string{"ls", "/"},
			expected: control.ExecArgs{
				Argv:             []string{"ls", "/"},
				Envv:             []string{"FOO=bar", "BAZ=new", "XYZ=xyz,BAZ=new"},
				WorkingDirectory: "/baz",
				KUID:             4,
				KGID:             4,
				ExtraKGIDs:       []auth.KGID{1, 2, 3, 4, 5, 6},
				Capabilities: &auth.TaskCapabilities{
					BoundingCaps:    auth.CapabilitySetOfMany([]linux.Capability{linux.CAP_DAC_OVERRIDE, linux.CAP_DAC_READ_SEARCH}),
					EffectiveCaps:   auth.CapabilitySetOfMany([]linux.Capability{linux.CAP_DAC_READ_SEARCH}),
					PermittedCaps:   auth.CapabilitySetOfMany([]linux.Capability{linux.CAP_DAC_READ_SEARCH}),
					InheritableCaps: auth.CapabilitySetOfMany([]linux.Capability{linux.CAP_DAC_OVERRIDE}),
					// TODO(gvisor.dev/issue/3166): Once ambient capabilities is
					// supported, AmbientCaps should be CAP_DAC_READ_SEARCH.
					AmbientCaps: 0,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := tc.ex.argsFromCLI(&tc.spec, tc.argv, true)
			if err != nil {
				t.Errorf("argsFromCLI(%+v): got error: %+v", tc.ex, err)
				return
			}
			if diff := cmp.Diff(*e, tc.expected, cmpopts.IgnoreUnexported(os.File{})); diff != "" {
				t.Errorf("argsFromCLI(%+v): diff (+want -got):\n%s", tc.ex, diff)
			}
		})
	}
}

func TestJSONArgs(t *testing.T) {
	testCases := []struct {
		name     string
		ex       Exec
		spec     specs.Process
		p        specs.Process
		expected control.ExecArgs
	}{
		{
			name: "flags overridden by process file",
			ex: Exec{
				cwd:         "/baz/quux",
				user:        user{kuid: 1, kgid: 1},
				extraKGIDs:  []string{"4", "5", "6"},
				caps:        []string{"CAP_SETGID"},
				processPath: "/bin/foo",
			},
			spec: specs.Process{
				Capabilities: &specs.LinuxCapabilities{Bounding: []string{"CAP_DAC_READ_SEARCH"}},
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
		{
			name: "capabilities fallback to spec",
			ex:   Exec{},
			spec: specs.Process{
				Capabilities: &specs.LinuxCapabilities{
					Bounding: []string{"CAP_DAC_READ_SEARCH"}},
			},
			p: specs.Process{
				User: specs.User{UID: 0, GID: 0},
				Args: []string{"ls", "/"},
				Cwd:  "/foo/bar",
				// Does not specify capabilities.
			},
			expected: control.ExecArgs{
				Argv:             []string{"ls", "/"},
				WorkingDirectory: "/foo/bar",
				KUID:             0,
				KGID:             0,
				ExtraKGIDs:       []auth.KGID{},
				Capabilities: &auth.TaskCapabilities{
					BoundingCaps: auth.CapabilitySetOf(linux.CAP_DAC_READ_SEARCH),
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := argsFromProcess(&tc.spec, &tc.p, true)
			if err != nil {
				t.Errorf("argsFromProcess(%+v): got error: %+v", tc.p, err)
				return
			}
			if diff := cmp.Diff(*e, tc.expected, cmpopts.IgnoreUnexported(os.File{})); diff != "" {
				t.Errorf("argsFromProcess(%+v): diff (+want -got):\n%s", tc.p, diff)
			}
		})
	}
}
