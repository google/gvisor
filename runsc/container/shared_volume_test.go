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

package container

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/test/testutil"
)

// TestSharedVolume checks that modifications to a volume mount are propagated
// into and out of the sandbox.
func TestSharedVolume(t *testing.T) {
	conf := testutil.TestConfig()
	conf.FileAccess = boot.FileAccessShared
	t.Logf("Running test with conf: %+v", conf)

	// Main process just sleeps. We will use "exec" to probe the state of
	// the filesystem.
	spec := testutil.NewSpecWithArgs("sleep", "1000")

	dir, err := ioutil.TempDir(testutil.TmpDir(), "shared-volume-test")
	if err != nil {
		t.Fatalf("TempDir failed: %v", err)
	}

	rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create and start the container.
	args := Args{
		ID:        testutil.UniqueContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	c, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer c.Destroy()
	if err := c.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	// File that will be used to check consistency inside/outside sandbox.
	filename := filepath.Join(dir, "file")

	// File does not exist yet. Reading from the sandbox should fail.
	argsTestFile := &control.ExecArgs{
		Filename: "/usr/bin/test",
		Argv:     []string{"test", "-f", filename},
	}
	if ws, err := c.executeSync(argsTestFile); err != nil {
		t.Fatalf("unexpected error testing file %q: %v", filename, err)
	} else if ws.ExitStatus() == 0 {
		t.Errorf("test %q exited with code %v, wanted not zero", ws.ExitStatus(), err)
	}

	// Create the file from outside of the sandbox.
	if err := ioutil.WriteFile(filename, []byte("foobar"), 0777); err != nil {
		t.Fatalf("error writing to file %q: %v", filename, err)
	}

	// Now we should be able to test the file from within the sandbox.
	if ws, err := c.executeSync(argsTestFile); err != nil {
		t.Fatalf("unexpected error testing file %q: %v", filename, err)
	} else if ws.ExitStatus() != 0 {
		t.Errorf("test %q exited with code %v, wanted zero", filename, ws.ExitStatus())
	}

	// Rename the file from outside of the sandbox.
	newFilename := filepath.Join(dir, "newfile")
	if err := os.Rename(filename, newFilename); err != nil {
		t.Fatalf("os.Rename(%q, %q) failed: %v", filename, newFilename, err)
	}

	// File should no longer exist at the old path within the sandbox.
	if ws, err := c.executeSync(argsTestFile); err != nil {
		t.Fatalf("unexpected error testing file %q: %v", filename, err)
	} else if ws.ExitStatus() == 0 {
		t.Errorf("test %q exited with code %v, wanted not zero", filename, ws.ExitStatus())
	}

	// We should be able to test the new filename from within the sandbox.
	argsTestNewFile := &control.ExecArgs{
		Filename: "/usr/bin/test",
		Argv:     []string{"test", "-f", newFilename},
	}
	if ws, err := c.executeSync(argsTestNewFile); err != nil {
		t.Fatalf("unexpected error testing file %q: %v", newFilename, err)
	} else if ws.ExitStatus() != 0 {
		t.Errorf("test %q exited with code %v, wanted zero", newFilename, ws.ExitStatus())
	}

	// Delete the renamed file from outside of the sandbox.
	if err := os.Remove(newFilename); err != nil {
		t.Fatalf("error removing file %q: %v", filename, err)
	}

	// Renamed file should no longer exist at the old path within the sandbox.
	if ws, err := c.executeSync(argsTestNewFile); err != nil {
		t.Fatalf("unexpected error testing file %q: %v", newFilename, err)
	} else if ws.ExitStatus() == 0 {
		t.Errorf("test %q exited with code %v, wanted not zero", newFilename, ws.ExitStatus())
	}

	// Now create the file from WITHIN the sandbox.
	argsTouch := &control.ExecArgs{
		Filename: "/usr/bin/touch",
		Argv:     []string{"touch", filename},
		KUID:     auth.KUID(os.Getuid()),
		KGID:     auth.KGID(os.Getgid()),
	}
	if ws, err := c.executeSync(argsTouch); err != nil {
		t.Fatalf("unexpected error touching file %q: %v", filename, err)
	} else if ws.ExitStatus() != 0 {
		t.Errorf("touch %q exited with code %v, wanted zero", filename, ws.ExitStatus())
	}

	// File should exist outside the sandbox.
	if _, err := os.Stat(filename); err != nil {
		t.Errorf("stat %q got error %v, wanted nil", filename, err)
	}

	// File should exist outside the sandbox.
	if _, err := os.Stat(filename); err != nil {
		t.Errorf("stat %q got error %v, wanted nil", filename, err)
	}

	// Delete the file from within the sandbox.
	argsRemove := &control.ExecArgs{
		Filename: "/bin/rm",
		Argv:     []string{"rm", filename},
	}
	if ws, err := c.executeSync(argsRemove); err != nil {
		t.Fatalf("unexpected error removing file %q: %v", filename, err)
	} else if ws.ExitStatus() != 0 {
		t.Errorf("remove %q exited with code %v, wanted zero", filename, ws.ExitStatus())
	}

	// File should not exist outside the sandbox.
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		t.Errorf("stat %q got error %v, wanted ErrNotExist", filename, err)
	}
}

func checkFile(c *Container, filename string, want []byte) error {
	cpy := filename + ".copy"
	argsCp := &control.ExecArgs{
		Filename: "/bin/cp",
		Argv:     []string{"cp", "-f", filename, cpy},
	}
	if _, err := c.executeSync(argsCp); err != nil {
		return fmt.Errorf("unexpected error copying file %q to %q: %v", filename, cpy, err)
	}
	got, err := ioutil.ReadFile(cpy)
	if err != nil {
		return fmt.Errorf("Error reading file %q: %v", filename, err)
	}
	if !bytes.Equal(got, want) {
		return fmt.Errorf("file content inside the sandbox is wrong, got: %q, want: %q", got, want)
	}
	return nil
}

// TestSharedVolumeFile tests that changes to file content outside the sandbox
// is reflected inside.
func TestSharedVolumeFile(t *testing.T) {
	conf := testutil.TestConfig()
	conf.FileAccess = boot.FileAccessShared
	t.Logf("Running test with conf: %+v", conf)

	// Main process just sleeps. We will use "exec" to probe the state of
	// the filesystem.
	spec := testutil.NewSpecWithArgs("sleep", "1000")

	dir, err := ioutil.TempDir(testutil.TmpDir(), "shared-volume-test")
	if err != nil {
		t.Fatalf("TempDir failed: %v", err)
	}

	rootDir, bundleDir, err := testutil.SetupContainer(spec, conf)
	if err != nil {
		t.Fatalf("error setting up container: %v", err)
	}
	defer os.RemoveAll(rootDir)
	defer os.RemoveAll(bundleDir)

	// Create and start the container.
	args := Args{
		ID:        testutil.UniqueContainerID(),
		Spec:      spec,
		BundleDir: bundleDir,
	}
	c, err := New(conf, args)
	if err != nil {
		t.Fatalf("error creating container: %v", err)
	}
	defer c.Destroy()
	if err := c.Start(conf); err != nil {
		t.Fatalf("error starting container: %v", err)
	}

	// File that will be used to check consistency inside/outside sandbox.
	filename := filepath.Join(dir, "file")

	// Write file from outside the container and check that the same content is
	// read inside.
	want := []byte("host-")
	if err := ioutil.WriteFile(filename, []byte(want), 0666); err != nil {
		t.Fatalf("Error writing to %q: %v", filename, err)
	}
	if err := checkFile(c, filename, want); err != nil {
		t.Fatal(err.Error())
	}

	// Append to file inside the container and check that content is not lost.
	argsAppend := &control.ExecArgs{
		Filename: "/bin/bash",
		Argv:     []string{"bash", "-c", "echo -n sandbox- >> " + filename},
	}
	if _, err := c.executeSync(argsAppend); err != nil {
		t.Fatalf("unexpected error appending file %q: %v", filename, err)
	}
	want = []byte("host-sandbox-")
	if err := checkFile(c, filename, want); err != nil {
		t.Fatal(err.Error())
	}

	// Write again from outside the container and check that the same content is
	// read inside.
	f, err := os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("Error openning file %q: %v", filename, err)
	}
	defer f.Close()
	if _, err := f.Write([]byte("host")); err != nil {
		t.Fatalf("Error writing to file %q: %v", filename, err)
	}
	want = []byte("host-sandbox-host")
	if err := checkFile(c, filename, want); err != nil {
		t.Fatal(err.Error())
	}

	// Shrink file outside and check that the same content is read inside.
	if err := f.Truncate(5); err != nil {
		t.Fatalf("Error truncating file %q: %v", filename, err)
	}
	want = want[:5]
	if err := checkFile(c, filename, want); err != nil {
		t.Fatal(err.Error())
	}
}
