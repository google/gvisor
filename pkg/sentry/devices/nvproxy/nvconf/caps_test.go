// Copyright 2026 The gVisor Authors.
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

package nvconf

import (
	"slices"
	"testing"
)

// TestNVIDIAFlagsSkipsPrivilegedCaps is a regression test for the
// container-startup bug seen when NVIDIA_DRIVER_CAPABILITIES=all is combined
// with --nvproxy-allowed-driver-capabilities using priviledged capabilities.
//
// In that configuration, NVProxyDriverCapsFromEnv returns the full allowed set,
// which includes CapProfiling. nvproxySetup then calls NVIDIAFlags() on that set
// to build the `nvidia-container-cli configure` argv. CapProfiling (and
// CapFabricIMEXManagement) are handled internally by nvproxy and have no
// nvidia-container-cli flag, so NVIDIAFlags() must silently skip them rather
// than panic (which previously crashed runsc with exit status 2).
func TestNVIDIAFlagsSkipsPrivilegedCaps(t *testing.T) {
	for _, tc := range []struct {
		name string
		caps DriverCaps
		want []string
	}{
		{
			name: "all_plus_profiling",
			caps: AllContainerDriverCaps | CapProfiling,
			want: []string{"--compute", "--graphics", "--utility", "--video"},
		},
		{
			name: "profiling_only",
			caps: CapProfiling,
			want: nil,
		},
		{
			name: "fabric_imex_only",
			caps: CapFabricIMEXManagement,
			want: nil,
		},
		{
			name: "compute_and_profiling",
			caps: CapCompute | CapProfiling,
			want: []string{"--compute"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.caps.NVIDIAFlags()
			slices.Sort(got)
			slices.Sort(tc.want)
			if !slices.Equal(got, tc.want) {
				t.Errorf("NVIDIAFlags() = %v, want %v", got, tc.want)
			}
		})
	}
}
