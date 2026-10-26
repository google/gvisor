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

package filter

import (
	"fmt"
	"testing"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/platform/kvm"
	"gvisor.dev/gvisor/pkg/sentry/platform/systrap"
	"gvisor.dev/gvisor/runsc/boot/filter/config"
)

func TestPrecompiledFilestoreReflink(t *testing.T) {
	if PrecompilationDisabledAtBuildTime {
		t.Skip("seccomp precompilation is disabled in this build; run with -c opt")
	}
	for _, plat := range []platform.SeccompInfo{(&systrap.Systrap{}).SeccompInfo(), (&kvm.KVM{}).SeccompInfo()} {
		for _, directfs := range []bool{false, true} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/directfs=%t/reflink=%t", plat.ConfigKey(), directfs, enabled), func(t *testing.T) {
					opt := config.Options{
						Platform:         plat,
						HostFilesystem:   directfs,
						FilestoreReflink: enabled,
						ControllerFD:     17,
						ProcSelfFD:       19,
					}
					program, ok := GetPrecompiled(opt.ConfigKey())
					if !ok {
						t.Fatalf("no precompiled program for %s", opt.ConfigKey())
					}
					insns, err := program.RenderInstructions(opt.Vars())
					if err != nil {
						t.Fatalf("RenderInstructions: %v", err)
					}
					compiled, err := bpf.Compile(insns, true /* optimize */)
					if err != nil {
						t.Fatal(err)
					}
					for _, args := range [][6]uint64{
						{3, uint64(linux.FICLONE), 4},
						{^uint64(0), uint64(linux.FICLONE), 4},
						{3, uint64(linux.FICLONE), ^uint64(0)},
					} {
						data := linux.SeccompData{Nr: unix.SYS_IOCTL, Arch: seccomp.LINUX_AUDIT_ARCH, Args: args}
						got, err := bpf.Exec[bpf.NativeEndian](compiled, seccomp.DataAsBPFInput(&data, make([]byte, data.SizeBytes())))
						if err != nil {
							t.Fatal(err)
						}
						want := enabled && args[0] == 3 && args[2] == 4
						if allowed := got == uint32(linux.SECCOMP_RET_ALLOW); allowed != want {
							t.Errorf("args=%v action=%#x, want allowed=%t", args, got, want)
						}
					}
				})
			}
		}
	}
}
