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

// Package testutil provides utility function to assist with unit tests that
// require a [partialy] functioning kernel.
package testutil

import (
	"fmt"
	"os"
	"runtime"

	"flag"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/loader"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/time"

	// Platforms are plugable.
	_ "gvisor.dev/gvisor/pkg/sentry/platform/kvm"
	_ "gvisor.dev/gvisor/pkg/sentry/platform/ptrace"
)

var (
	platformFlag = flag.String("platform", "ptrace", "specify which platform to use")
)

// Boot initializes a new bare bones kernel for test.
func Boot() (*kernel.Kernel, error) {
	platformCtr, err := platform.Lookup(*platformFlag)
	if err != nil {
		return nil, fmt.Errorf("platform not found: %v", err)
	}
	deviceFile, err := platformCtr.OpenDevice()
	if err != nil {
		return nil, fmt.Errorf("creating platform: %v", err)
	}
	plat, err := platformCtr.New(deviceFile)
	if err != nil {
		return nil, fmt.Errorf("creating platform: %v", err)
	}

	k := &kernel.Kernel{
		Platform: plat,
	}

	mf, err := createMemoryFile()
	if err != nil {
		return nil, err
	}
	k.SetMemoryFile(mf)

	// Pass k as the platform since it is savable, unlike the actual platform.
	// FIXME(b/109889800): Use non-nil context.
	vdso, err := loader.PrepareVDSO(nil, k)
	if err != nil {
		return nil, fmt.Errorf("creating vdso: %v", err)
	}

	// Create timekeeper.
	tk, err := kernel.NewTimekeeper(k, vdso.ParamPage.FileRange())
	if err != nil {
		return nil, fmt.Errorf("creating timekeeper: %v", err)
	}
	tk.SetClocks(time.NewCalibratedClocks())

	creds := auth.NewRootCredentials(auth.NewRootUserNamespace())

	// Initiate the Kernel object, which is required by the Context passed
	// to createVFS in order to mount (among other things) procfs.
	if err = k.Init(kernel.InitKernelArgs{
		ApplicationCores:            uint(runtime.GOMAXPROCS(-1)),
		FeatureSet:                  cpuid.HostFeatureSet(),
		Timekeeper:                  tk,
		RootUserNamespace:           creds.UserNamespace,
		Vdso:                        vdso,
		RootUTSNamespace:            kernel.NewUTSNamespace("hostname", "domain", creds.UserNamespace),
		RootIPCNamespace:            kernel.NewIPCNamespace(creds.UserNamespace),
		RootAbstractSocketNamespace: kernel.NewAbstractSocketNamespace(),
		PIDNamespace:                kernel.NewRootPIDNamespace(creds.UserNamespace),
	}); err != nil {
		return nil, fmt.Errorf("initializing kernel: %v", err)
	}

	ctx := k.SupervisorContext()

	// Create mount namespace without root as it's the minimum required to create
	// the global thread group.
	mntns, err := fs.NewMountNamespace(ctx, nil)
	if err != nil {
		return nil, err
	}
	ls, err := limits.NewLinuxLimitSet()
	if err != nil {
		return nil, err
	}
	tg := k.NewThreadGroup(mntns, k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, ls)
	k.SetGlobalInit(tg)

	return k, nil
}

// CreateTask create a new bare bones task for tests.
func CreateTask(ctx context.Context, name string, tc *kernel.ThreadGroup) (*kernel.Task, error) {
	k := kernel.KernelFromContext(ctx)
	config := &kernel.TaskConfig{
		Kernel:                  k,
		ThreadGroup:             tc,
		TaskContext:             &kernel.TaskContext{Name: name},
		Credentials:             auth.CredentialsFromContext(ctx),
		AllowedCPUMask:          sched.NewFullCPUSet(k.ApplicationCores()),
		UTSNamespace:            kernel.UTSNamespaceFromContext(ctx),
		IPCNamespace:            kernel.IPCNamespaceFromContext(ctx),
		AbstractSocketNamespace: kernel.NewAbstractSocketNamespace(),
	}
	return k.TaskSet().NewTask(config)
}

func createMemoryFile() (*pgalloc.MemoryFile, error) {
	const memfileName = "test-memory"
	memfd, err := memutil.CreateMemFD(memfileName, 0)
	if err != nil {
		return nil, fmt.Errorf("error creating memfd: %v", err)
	}
	memfile := os.NewFile(uintptr(memfd), memfileName)
	mf, err := pgalloc.NewMemoryFile(memfile, pgalloc.MemoryFileOpts{})
	if err != nil {
		memfile.Close()
		return nil, fmt.Errorf("error creating pgalloc.MemoryFile: %v", err)
	}
	return mf, nil
}
