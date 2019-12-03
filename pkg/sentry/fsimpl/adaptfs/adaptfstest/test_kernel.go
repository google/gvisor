// Copyright 2019 The gVisor Authors.
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

package adaptfstest

import (
	"os"
	"testing"

	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform/ptrace"
	"gvisor.dev/gvisor/pkg/sentry/usage"
	"gvisor.dev/gvisor/pkg/sentry/usermem"

	sentrytime "gvisor.dev/gvisor/pkg/sentry/time"
)

func newTestKernel(t *testing.T) *kernel.Kernel {
	if err := usage.Init(); err != nil {
		t.Fatalf("failed to initialize memory accounting globals: %v", err)
	}

	k := &kernel.Kernel{}

	const memfileName = "test-kernel-memory"
	memfd, err := memutil.CreateMemFD(memfileName, 0)
	if err != nil {
		t.Fatalf("failed to create memfd: %v", err)
	}
	mf, err := pgalloc.NewMemoryFile(os.NewFile(uintptr(memfd), memfileName), pgalloc.MemoryFileOpts{})
	if err != nil {
		t.Fatalf("failed to create memory file: %v", err)
	}
	k.SetMemoryFile(mf)

	ptracePlatform, err := ptrace.New()
	if err != nil {
		t.Fatalf("failed to create ptrace platform: %v", err)
	}
	k.Platform = ptracePlatform

	vdsoParamPage, err := mf.Allocate(usermem.PageSize, usage.System)
	if err != nil {
		t.Fatalf("failed to allocate VDSO parameter page: %v", err)
	}
	tk, err := kernel.NewTimekeeper(k, vdsoParamPage)
	if err != nil {
		t.Fatalf("failed to create timekeeper: %v", err)
	}
	tk.SetClocks(sentrytime.NewCalibratedClocks())

	userns := auth.NewRootUserNamespace()

	if err := k.Init(kernel.InitKernelArgs{
		FeatureSet:                  cpuid.HostFeatureSet(),
		Timekeeper:                  tk,
		RootUserNamespace:           userns,
		ApplicationCores:            2,
		RootUTSNamespace:            kernel.NewUTSNamespace("host", "domain", userns),
		RootIPCNamespace:            kernel.NewIPCNamespace(userns),
		RootAbstractSocketNamespace: kernel.NewAbstractSocketNamespace(),
		PIDNamespace:                kernel.NewRootPIDNamespace(userns),
	}); err != nil {
		t.Fatalf("failed to initialize kernel: %v", err)
	}

	return k
}
