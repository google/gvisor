// Copyright 2021 The gVisor Authors.
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

// Package fsstress runs fsstress tool inside a docker container.
package fsstress

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/docker/docker/api/types/mount"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/pkg/test/testutil"
)

func init() {
	rand.Seed(int64(time.Now().Nanosecond()))
}

func TestMain(m *testing.M) {
	dockerutil.EnsureSupportedDockerVersion()
	flag.Parse()
	os.Exit(m.Run())
}

type config struct {
	operations string
	processes  string
	target     string
	mounts     []mount.Mount
}

func fsstress(t *testing.T, conf config) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	const image = "basic/fsstress"
	seed := strconv.FormatUint(uint64(rand.Uint32()), 10)
	args := []string{"-d", conf.target, "-n", conf.operations, "-p", conf.processes, "-s", seed, "-X"}
	opts := dockerutil.RunOpts{
		Image:  image,
		Mounts: conf.mounts,
	}
	var mounts string
	if len(conf.mounts) > 0 {
		mounts = " -v "
		for _, m := range conf.mounts {
			mounts += fmt.Sprintf("-v <any_dir>:%s", m.Target)
		}
	}
	t.Logf("Repro: docker run --rm --runtime=%s%s gvisor.dev/images/%s %s", dockerutil.Runtime(), mounts, image, strings.Join(args, " "))
	out, err := d.Run(ctx, opts, args...)
	if err != nil {
		t.Fatalf("docker run failed: %v\noutput: %s", err, out)
	}
	// This is to catch cases where fsstress spews out error messages during clean
	// up but doesn't return error.
	if len(out) > 0 {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestFsstressGofer(t *testing.T) {
	// This takes between 30-60s to run on my machine. Adjust as needed.
	cfg := config{
		operations: "500",
		processes:  "20",
		target:     "/test",
	}
	fsstress(t, cfg)
}

func TestFsstressGoferShared(t *testing.T) {
	dir, err := ioutil.TempDir(testutil.TmpDir(), "fsstress")
	if err != nil {
		t.Fatalf("ioutil.TempDir() failed: %v", err)
	}
	defer os.RemoveAll(dir)

	// This takes between 30-60s to run on my machine. Adjust as needed.
	cfg := config{
		operations: "500",
		processes:  "20",
		target:     "/test",
		mounts: []mount.Mount{
			{
				Source: dir,
				Target: "/test",
				Type:   "bind",
			},
		},
	}
	fsstress(t, cfg)
}

func TestFsstressTmpfs(t *testing.T) {
	// This takes between 10s to run on my machine. Adjust as needed.
	cfg := config{
		operations: "5000",
		processes:  "20",
		target:     "/tmp",
	}
	fsstress(t, cfg)
}
