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

package sys_test

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/sys"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/testutil"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func newTestSystem(t *testing.T) *testutil.System {
	k, err := testutil.Boot()
	if err != nil {
		t.Fatalf("Failed to create test kernel: %v", err)
	}
	ctx := k.SupervisorContext()
	creds := auth.CredentialsFromContext(ctx)
	k.VFS().MustRegisterFilesystemType(sys.Name, sys.FilesystemType{}, &vfs.RegisterFilesystemTypeOptions{
		AllowUserMount: true,
	})

	mns, err := k.VFS().NewMountNamespace(ctx, creds, "", sys.Name, &vfs.MountOptions{})
	if err != nil {
		t.Fatalf("Failed to create new mount namespace: %v", err)
	}
	return testutil.NewSystem(ctx, t, k.VFS(), mns)
}

func TestReadCPUFile(t *testing.T) {
	s := newTestSystem(t)
	defer s.Destroy()
	k := kernel.KernelFromContext(s.Ctx)
	maxCPUCores := k.ApplicationCores()

	expected := fmt.Sprintf("0-%d\n", maxCPUCores-1)

	for _, fname := range []string{"online", "possible", "present"} {
		pop := s.PathOpAtRoot(fmt.Sprintf("devices/system/cpu/%s", fname))
		fd, err := s.VFS.OpenAt(s.Ctx, s.Creds, pop, &vfs.OpenOptions{})
		if err != nil {
			t.Fatalf("OpenAt(pop:%+v) = %+v failed: %v", pop, fd, err)
		}
		defer fd.DecRef(s.Ctx)
		content, err := s.ReadToEnd(fd)
		if err != nil {
			t.Fatalf("Read failed: %v", err)
		}
		if diff := cmp.Diff(expected, content); diff != "" {
			t.Fatalf("Read returned unexpected data:\n--- want\n+++ got\n%v", diff)
		}
	}
}

func TestSysRootContainsExpectedEntries(t *testing.T) {
	s := newTestSystem(t)
	defer s.Destroy()
	pop := s.PathOpAtRoot("/")
	s.AssertAllDirentTypes(s.ListDirents(pop), map[string]testutil.DirentType{
		"block":    linux.DT_DIR,
		"bus":      linux.DT_DIR,
		"class":    linux.DT_DIR,
		"dev":      linux.DT_DIR,
		"devices":  linux.DT_DIR,
		"firmware": linux.DT_DIR,
		"fs":       linux.DT_DIR,
		"kernel":   linux.DT_DIR,
		"module":   linux.DT_DIR,
		"power":    linux.DT_DIR,
	})
}

func TestCgroupMountpointExists(t *testing.T) {
	// Note: The mountpoint is only created if cgroups are available. This is
	// the VFS2 implementation of sysfs and the test runs with VFS2 enabled, so
	// we expect to see the mount point unconditionally.
	s := newTestSystem(t)
	defer s.Destroy()
	pop := s.PathOpAtRoot("/fs")
	s.AssertAllDirentTypes(s.ListDirents(pop), map[string]testutil.DirentType{
		"cgroup": linux.DT_DIR,
	})
	pop = s.PathOpAtRoot("/fs/cgroup")
	s.AssertAllDirentTypes(s.ListDirents(pop), map[string]testutil.DirentType{ /*empty*/ })
}
