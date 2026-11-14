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

package nvproxy

import (
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/contexttest"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

// TestProcfsVersionIsHostVersion checks that /proc/driver/nvidia/version
// holds the host's file verbatim, and does not exist when the host has none.
func TestProcfsVersionIsHostVersion(t *testing.T) {
	const hostVersion = "NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  610.57.04  Release Build  (dvs-builder@U22-I3-AF03-09-1)  Thu Oct  2 17:07:40 UTC 2026\nGCC version:  gcc version 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04)\n"
	Init()
	var driverVersion nvconf.DriverVersion
	for version := range abis {
		driverVersion = version
		break
	}
	for _, tc := range []struct {
		name        string
		hostVersion string
		wantExists  bool
	}{
		{
			name:        "host_has_version",
			hostVersion: hostVersion,
			wantExists:  true,
		},
		{
			name:        "host_has_no_version",
			hostVersion: "",
			wantExists:  false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := contexttest.Context(t)
			vfsObj := &vfs.VirtualFilesystem{}
			if err := vfsObj.Init(ctx); err != nil {
				t.Fatalf("vfsObj.Init() failed: %v", err)
			}
			if _, err := Register(vfsObj, &Options{
				DriverVersion:          driverVersion,
				AllowUnsupportedDriver: true,
				DriverCaps:             nvconf.CapCompute | nvconf.CapUtility,
				HostSettings: &nvconf.HostSettings{
					ProcDriverNvidiaParams:  "ModifyDeviceFiles: 1\n",
					ProcDriverNvidiaVersion: tc.hostVersion,
				},
			}); err != nil {
				t.Fatalf("Register() failed: %v", err)
			}
			got, exists := ProcfsInfoFromVFS(vfsObj).StaticFiles["version"]
			if exists != tc.wantExists {
				t.Fatalf("version exists = %t, want %t", exists, tc.wantExists)
			}
			if got != tc.hostVersion {
				t.Errorf("version = %q, want %q", got, tc.hostVersion)
			}
		})
	}
}
