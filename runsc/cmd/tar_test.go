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

package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/subcommands"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

func TestOpenOutputTarFile_RegularFile(t *testing.T) {
	tmpDir := t.TempDir()
	outPath := filepath.Join(tmpDir, "regular.tar")
	if err := os.WriteFile(outPath, []byte("old-payload-longer"), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", outPath, err)
	}

	f, err := openOutputTarFile(outPath)
	if err != nil {
		t.Fatalf("openOutputTarFile(%q) error = %v, want nil", outPath, err)
	}
	if _, err := f.Write([]byte("new")); err != nil {
		f.Close()
		t.Fatalf("f.Write() failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("f.Close() failed: %v", err)
	}

	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) failed: %v", outPath, err)
	}
	if string(got) != "new" {
		t.Errorf("file content = %q, want %q", string(got), "new")
	}
}

func TestOpenOutputTarFile_SymlinkRejected(t *testing.T) {
	tmpDir := t.TempDir()
	canaryPath := filepath.Join(tmpDir, "canary.txt")
	const wantCanary = "PROTECTED_CANARY_DATA"
	if err := os.WriteFile(canaryPath, []byte(wantCanary), 0644); err != nil {
		t.Fatalf("os.WriteFile(%q) failed: %v", canaryPath, err)
	}

	symlinkPath := filepath.Join(tmpDir, "symlink.tar")
	if err := os.Symlink(canaryPath, symlinkPath); err != nil {
		t.Fatalf("os.Symlink(%q, %q) failed: %v", canaryPath, symlinkPath, err)
	}

	f, err := openOutputTarFile(symlinkPath)
	if err == nil {
		f.Close()
		t.Fatalf("openOutputTarFile(%q) error = nil, want %v", symlinkPath, unix.ELOOP)
	}
	if !errors.Is(err, unix.ELOOP) {
		t.Errorf("openOutputTarFile(%q) error = %v, want %v", symlinkPath, err, unix.ELOOP)
	}

	gotCanary, err := os.ReadFile(canaryPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) failed: %v", canaryPath, err)
	}
	if string(gotCanary) != wantCanary {
		t.Errorf("canary content = %q, want %q", string(gotCanary), wantCanary)
	}
}

func TestOpenOutputTarFile_ProcSelfFD(t *testing.T) {
	tmpDir := t.TempDir()
	targetPath := filepath.Join(tmpDir, "proc_fd_target.tar")
	preOpened, err := os.OpenFile(targetPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil {
		t.Fatalf("os.OpenFile(%q) failed: %v", targetPath, err)
	}
	defer preOpened.Close()

	procFDPath := fmt.Sprintf("/proc/self/fd/%d", preOpened.Fd())
	f, err := openOutputTarFile(procFDPath)
	if err != nil {
		t.Fatalf("openOutputTarFile(%q) error = %v, want nil", procFDPath, err)
	}
	if _, err := f.Write([]byte("via-proc-fd")); err != nil {
		f.Close()
		t.Fatalf("f.Write() failed: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("f.Close() failed: %v", err)
	}

	got, err := os.ReadFile(targetPath)
	if err != nil {
		t.Fatalf("os.ReadFile(%q) failed: %v", targetPath, err)
	}
	if string(got) != "via-proc-fd" {
		t.Errorf("target content = %q, want %q", string(got), "via-proc-fd")
	}
}

func TestIsProcFDPath(t *testing.T) {
	for _, tc := range []struct {
		path string
		want bool
	}{
		{path: "/proc/self/fd/3", want: true},
		{path: "/proc/thread-self/fd/4", want: true},
		{path: "/dev/fd/5", want: true},
		{path: "/proc/self/fd/", want: false},
		{path: "/proc/self/fd/../1", want: false},
		{path: "/proc/self/fd/2147483648", want: false},
		{path: "/tmp/upper.tar", want: false},
	} {
		if got := isProcFDPath(tc.path); got != tc.want {
			t.Errorf("isProcFDPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestRootfsUpperExecute(t *testing.T) {
	conf := testutil.TestConfig(t)
	conf.Overlay2.Set("root:memory")
	spec := testutil.NewSpecWithArgs("/bin/sleep", "10000")
	spec.Root.Readonly = false

	_, bundleDir, cleanup, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("SetupContainer() failed: %v", err)
	}
	defer cleanup()

	id := testutil.RandomContainerID()
	cont, err := container.New(conf, container.Args{
		ID:        id,
		Spec:      spec,
		BundleDir: bundleDir,
	})
	if err != nil {
		t.Fatalf("container.New() failed: %v", err)
	}
	defer cont.Destroy()
	if err := cont.Start(conf); err != nil {
		t.Fatalf("cont.Start() failed: %v", err)
	}

	outPath := filepath.Join(t.TempDir(), "upper.tar")
	r := RootfsUpper{}
	f := flag.NewFlagSet("rootfs-upper", flag.ContinueOnError)
	r.SetFlags(f)
	if err := f.Parse([]string{"--file=" + outPath, id}); err != nil {
		t.Fatalf("f.Parse() failed: %v", err)
	}
	if status := r.Execute(context.Background(), f, conf); status != subcommands.ExitSuccess {
		t.Fatalf("r.Execute() = %v, want %v", status, subcommands.ExitSuccess)
	}
	info, err := os.Stat(outPath)
	if err != nil {
		t.Fatalf("os.Stat(%q) failed: %v", outPath, err)
	}
	if info.Size() == 0 {
		t.Errorf("upper tar file %q is empty, want non-empty tar stream", outPath)
	}
}
