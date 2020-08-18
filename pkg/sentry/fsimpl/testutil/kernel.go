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

package testutil

import (
	"flag"
	"fmt"
	"os"
	"runtime"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/cpuid"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/memutil"
	"gvisor.dev/gvisor/pkg/sentry/fsbridge"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/kernel/sched"
	"gvisor.dev/gvisor/pkg/sentry/limits"
	"gvisor.dev/gvisor/pkg/sentry/loader"
	"gvisor.dev/gvisor/pkg/sentry/mm"
	"gvisor.dev/gvisor/pkg/sentry/pgalloc"
	"gvisor.dev/gvisor/pkg/sentry/platform"
	"gvisor.dev/gvisor/pkg/sentry/time"
	"gvisor.dev/gvisor/pkg/sentry/vfs"

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

	kernel.VFS2Enabled = true
	k := &kernel.Kernel{
		Platform: plat,
	}

	mf, err := createMemoryFile()
	if err != nil {
		return nil, err
	}
	k.SetMemoryFile(mf)

	// Pass k as the platform since it is savable, unlike the actual platform.
	vdso, err := loader.PrepareVDSO(k)
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

	k.VFS().MustRegisterFilesystemType(tmpfs.Name, &tmpfs.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
		AllowUserList:  true,
	})

	ls, err := limits.NewLinuxLimitSet()
	if err != nil {
		return nil, err
	}
	tg := k.NewThreadGroup(nil, k.RootPIDNamespace(), kernel.NewSignalHandlers(), linux.SIGCHLD, ls)
	k.TestOnly_SetGlobalInit(tg)

	return k, nil
}

// CreateTask creates a new bare bones task for tests.
func CreateTask(ctx context.Context, name string, tc *kernel.ThreadGroup, mntns *vfs.MountNamespace, root, cwd vfs.VirtualDentry) (*kernel.Task, error) {
	k := kernel.KernelFromContext(ctx)
	if k == nil {
		return nil, fmt.Errorf("cannot find kernel from context")
	}

	exe, err := newFakeExecutable(ctx, k.VFS(), auth.CredentialsFromContext(ctx), root)
	if err != nil {
		return nil, err
	}
	m := mm.NewMemoryManager(k, k, k.SleepForAddressSpaceActivation)
	m.SetExecutable(ctx, fsbridge.NewVFSFile(exe))

	config := &kernel.TaskConfig{
		Kernel:                  k,
		ThreadGroup:             tc,
		TaskContext:             &kernel.TaskContext{Name: name, MemoryManager: m},
		Credentials:             auth.CredentialsFromContext(ctx),
		NetworkNamespace:        k.RootNetworkNamespace(),
		AllowedCPUMask:          sched.NewFullCPUSet(k.ApplicationCores()),
		UTSNamespace:            kernel.UTSNamespaceFromContext(ctx),
		IPCNamespace:            kernel.IPCNamespaceFromContext(ctx),
		AbstractSocketNamespace: kernel.NewAbstractSocketNamespace(),
		MountNamespaceVFS2:      mntns,
		FSContext:               kernel.NewFSContextVFS2(root, cwd, 0022),
		FDTable:                 k.NewFDTable(),
	}
	return k.TaskSet().NewTask(config)
}

func newFakeExecutable(ctx context.Context, vfsObj *vfs.VirtualFilesystem, creds *auth.Credentials, root vfs.VirtualDentry) (*vfs.FileDescription, error) {
	const name = "executable"
	pop := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(name),
	}
	opts := &vfs.OpenOptions{
		Flags: linux.O_RDONLY | linux.O_CREAT,
		Mode:  0777,
	}
	return vfsObj.OpenAt(ctx, creds, pop, opts)
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
