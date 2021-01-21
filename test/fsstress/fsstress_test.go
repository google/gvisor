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
	"math/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

func init() {
	rand.Seed(int64(time.Now().Nanosecond()))
}

func fsstress(t *testing.T, dir string) {
	ctx := context.Background()
	d := dockerutil.MakeContainer(ctx, t)
	defer d.CleanUp(ctx)

	const (
		operations = "10000"
		processes  = "100"
		image      = "basic/fsstress"
	)
	seed := strconv.FormatUint(uint64(rand.Uint32()), 10)
	args := []string{"-d", dir, "-n", operations, "-p", processes, "-s", seed, "-X"}
	t.Logf("Repro: docker run --rm --runtime=runsc %s %s", image, strings.Join(args, ""))
	out, err := d.Run(ctx, dockerutil.RunOpts{Image: image}, args...)
	if err != nil {
		t.Fatalf("docker run failed: %v\noutput: %s", err, out)
	}
	lines := strings.SplitN(out, "\n", 2)
	if len(lines) > 1 || !strings.HasPrefix(out, "seed =") {
		t.Fatalf("unexpected output: %s", out)
	}
}

func TestFsstressGofer(t *testing.T) {
	fsstress(t, "/test")
}

func TestFsstressTmpfs(t *testing.T) {
	fsstress(t, "/tmp")
}
