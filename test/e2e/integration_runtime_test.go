// Copyright 2022 The gVisor Authors.
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

// Package integration provides end-to-end integration tests for runsc.
//
// Each test calls docker commands to start up a container, and tests that it is
// behaving properly, with various runsc commands. The container is killed and
// deleted at the end.
//
// Setup instruction in test/README.md.
package integration

import (
	"context"
	"flag"
	"io/ioutil"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/mount"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

const (
	// defaultWait is the default wait time used for tests.
	defaultWait = time.Minute

	memInfoCmd = "cat /proc/meminfo | grep MemTotal: | awk '{print $2}'"
)

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}

func TestRlimitNoFile(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-fdlimit")
	defer d.CleanUp(ctx)

	// Create a directory with a bunch of files.
	const nfiles = 5000
	tmpDir := testutil.TmpDir()
	for i := 0; i < nfiles; i++ {
		if _, err := ioutil.TempFile(tmpDir, "tmp"); err != nil {
			t.Fatalf("TempFile(): %v", err)
		}
	}

	// Run the container. Open a bunch of files simutaneously and sleep a bit
	// to give time for everything to start. We should hit the FD limit and
	// fail rather than waiting the full sleep duration.
	cmd := `for file in /tmp/foo/*; do (cat > "${file}") & done && sleep 60`
	got, err := d.Run(ctx, dockerutil.RunOpts{
		Image: "basic/ubuntu",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: tmpDir,
				Target: "/tmp/foo",
			},
		},
	}, "bash", "-c", cmd)
	if err == nil {
		t.Fatalf("docker run didn't fail: %s", got)
	} else if strings.Contains(err.Error(), "Unknown runtime specified") {
		t.Fatalf("docker failed because -fdlimit runtime was not installed")
	}
}

func TestDentryCacheLimit(t *testing.T) {
	ctx := context.Background()
	d := dockerutil.MakeContainerWithRuntime(ctx, t, "-dcache")
	defer d.CleanUp(ctx)

	// Create a directory with a bunch of files.
	const nfiles = 5000
	tmpDir := testutil.TmpDir()
	for i := 0; i < nfiles; i++ {
		if _, err := ioutil.TempFile(tmpDir, "tmp"); err != nil {
			t.Fatalf("TempFile(): %v", err)
		}
	}

	// Run the container. Open a bunch of files simutaneously and sleep a bit
	// to give time for everything to start. We shouldn't hit the FD limit
	// because the dentry cache is small.
	cmd := `for file in /tmp/foo/*; do (cat > "${file}") & done && sleep 10`
	got, err := d.Run(ctx, dockerutil.RunOpts{
		Image: "basic/ubuntu",
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: tmpDir,
				Target: "/tmp/foo",
			},
		},
	}, "bash", "-c", cmd)
	if err != nil {
		t.Fatalf("docker failed: %v, %s", err, got)
	}
}
