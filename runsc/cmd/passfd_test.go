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
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/testutil"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Exercise the CLI rather than container.Args: flags must reach the new
// sandbox, including when restore creates it or a separate create precedes it.
func TestPassFDCLI(t *testing.T) {
	for _, mode := range []string{"run", "create", "restore-new", "restore-created"} {
		t.Run(mode, func(t *testing.T) {
			conf := testutil.TestConfig(t)
			spec := testutil.NewSpecWithArgs("/bin/sleep", "10000")
			_, bundle, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			id := testutil.RandomContainerID()
			command := func(files []*os.File, args ...string) *exec.Cmd {
				cmd := exec.Command(specutils.ExePath, append(conf.ToFlags(), args...)...)
				cmd.ExtraFiles = files
				return cmd
			}
			run := func(files []*os.File, args ...string) {
				t.Helper()
				cmd := command(files, args...)
				// Detached containers retain stdio, so avoid output pipes
				// whose EOF would wait for the container to exit.
				cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
				if err := cmd.Run(); err != nil {
					t.Fatalf("runsc %v: %v", args, err)
				}
			}
			defer func() {
				if out, err := command(nil, "delete", "--force", id).CombinedOutput(); err != nil {
					t.Errorf("deleting container: %v\n%s", err, out)
				}
			}()
			openOutput := func(name string) *os.File {
				t.Helper()
				f, err := os.Create(filepath.Join(t.TempDir(), name))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { f.Close() })
				return f
			}
			checkOutput := func(f *os.File, want string) {
				t.Helper()
				got, err := os.ReadFile(f.Name())
				if err != nil || string(got) != want {
					t.Fatalf("passed file: got %q, err %v; want %q", got, err, want)
				}
			}
			before := openOutput("before")
			if mode == "run" {
				run([]*os.File{before}, "run", "--detach", "--pass-fd=3:3,3:4", "--bundle", bundle, id)
			} else {
				run([]*os.File{before}, "create", "--pass-fd=3:3,3:4", "--bundle", bundle, id)
				run(nil, "start", id)
			}
			run(nil, "exec", id, "/bin/sh", "-c", "printf before > /proc/1/fd/3; printf before >> /proc/1/fd/4")
			checkOutput(before, "beforebefore")
			if mode == "run" || mode == "create" {
				return
			}

			checkpoint := t.TempDir()
			run(nil, "checkpoint", "--image-path", checkpoint, id)
			run(nil, "delete", "--force", id)
			after := openOutput("after")
			restoreArgs := []string{"restore", "--detach", "--image-path", checkpoint, "--bundle", bundle}
			if mode == "restore-created" {
				run([]*os.File{after}, "create", "--pass-fd=3:3,3:4", "--bundle", bundle, id)
				args := append(append([]string{}, restoreArgs...), "--pass-fd=3:3,3:4", id)
				out, err := command([]*os.File{before}, args...).CombinedOutput()
				if err == nil || !strings.Contains(string(out), "pass-fd must be supplied when creating") {
					t.Fatalf("replacement mapping: got err %v, output %s", err, out)
				}
				run(nil, append(restoreArgs, id)...)
			} else {
				run([]*os.File{after}, append(restoreArgs, "--pass-fd=3:3,3:4", id)...)
			}
			run(nil, "exec", id, "/bin/sh", "-c", "printf after > /proc/1/fd/3; printf after >> /proc/1/fd/4")
			checkOutput(after, "afterafter")
			checkOutput(before, "beforebefore")
		})
	}
}

func TestPassFDSubcontainerCLI(t *testing.T) {
	for _, mode := range []string{"run", "create", "restore"} {
		t.Run(mode, func(t *testing.T) {
			conf := testutil.TestConfig(t)
			spec := testutil.NewSpecWithArgs("/bin/true")
			spec.Annotations[specutils.ContainerdContainerTypeAnnotation] = specutils.ContainerdContainerTypeContainer
			spec.Annotations[specutils.ContainerdSandboxIDAnnotation] = testutil.RandomContainerID()
			_, bundle, cleanup, err := testutil.SetupContainer(spec, conf)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			file, err := os.Create(filepath.Join(t.TempDir(), "output"))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			args := append(conf.ToFlags(), mode, "--pass-fd=3:3", "--bundle", bundle)
			if mode == "restore" {
				args = append(args, "--image-path", t.TempDir())
			}
			args = append(args, testutil.RandomContainerID())
			cmd := exec.Command(specutils.ExePath, args...)
			cmd.ExtraFiles = []*os.File{file}
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "passed files are supported only when creating a new sandbox") {
				t.Fatalf("subcontainer mapping: got err %v, output %s", err, out)
			}
		})
	}
}
