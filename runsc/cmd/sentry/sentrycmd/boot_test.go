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

package sentrycmd

import (
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
	"gvisor.dev/gvisor/runsc/flag"
)

func TestBootNvidiaHostVersionFlag(t *testing.T) {
	const wantVersion = "NVRM version: NVIDIA UNIX x86_64 Kernel Module  610.57.04\n"
	b := &Boot{}
	f := flag.NewFlagSet("test", flag.ContinueOnError)
	b.SetFlags(f)
	if err := f.Parse([]string{"--nvidia-host-version=" + wantVersion}); err != nil {
		t.Fatalf("f.Parse() failed: %v", err)
	}
	if b.procDriverNvidiaVersion != wantVersion {
		t.Errorf("procDriverNvidiaVersion = %q, want %q", b.procDriverNvidiaVersion, wantVersion)
	}
	if got := b.nvidiaHostSettings().ProcDriverNvidiaVersion; got != wantVersion {
		t.Errorf("nvidiaHostSettings().ProcDriverNvidiaVersion = %q, want %q", got, wantVersion)
	}
}

func TestBootApplyNvidiaHostSettings(t *testing.T) {
	b := &Boot{
		nvidiaFabricIMEXManagementDevMinor: -1,
		nvidiaMNCCManagementDevMinor:       -1,
	}
	argOverride := make(map[string]string)
	want := &nvconf.HostSettings{
		ProcDriverNvidiaParams:       "ModifyDeviceFiles: 1\n",
		ProcDriverNvidiaVersion:      "NVRM version: 610.57.04\n",
		HaveFabricIMEXManagement:     true,
		FabricIMEXManagementDevMinor: 3,
		HaveMNCCManagement:           true,
		MNCCManagementDevMinor:       4,
	}
	b.applyNvidiaHostSettings(want, argOverride)

	if argOverride["nvidia-host-params"] != want.ProcDriverNvidiaParams {
		t.Errorf("argOverride[nvidia-host-params] = %q, want %q", argOverride["nvidia-host-params"], want.ProcDriverNvidiaParams)
	}
	if argOverride["nvidia-host-version"] != want.ProcDriverNvidiaVersion {
		t.Errorf("argOverride[nvidia-host-version] = %q, want %q", argOverride["nvidia-host-version"], want.ProcDriverNvidiaVersion)
	}
	if argOverride["nvidia-fabric-imex-mgmt-minor"] != "3" {
		t.Errorf("argOverride[nvidia-fabric-imex-mgmt-minor] = %q, want %q", argOverride["nvidia-fabric-imex-mgmt-minor"], "3")
	}
	if argOverride["nvidia-mncc-mgmt-minor"] != "4" {
		t.Errorf("argOverride[nvidia-mncc-mgmt-minor] = %q, want %q", argOverride["nvidia-mncc-mgmt-minor"], "4")
	}

	got := b.nvidiaHostSettings()
	if *got != *want {
		t.Errorf("nvidiaHostSettings() = %+v, want %+v", *got, *want)
	}
}
