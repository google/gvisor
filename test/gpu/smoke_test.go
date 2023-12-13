// Copyright 2023 The gVisor Authors.
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

// Package smoke_test tests basic GPU functionality.
package smoke_test

import (
	"context"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

func TestGPUHello(t *testing.T) {
	ctx := context.Background()
	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)

	opts := dockerutil.GPURunOpts()
	opts.Image = "basic/cuda-vector-add"
	out, err := c.Run(ctx, opts)
	if err != nil {
		t.Fatalf("could not run cuda-vector-add: %v", err)
	}
	t.Logf("cuda-vector-add output: %s", string(out))
}

func TestCUDATests(t *testing.T) {
	ctx := context.Background()
	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)

	opts := dockerutil.GPURunOpts()
	opts.Image = "gpu/cuda-tests"
	out, err := c.Run(ctx, opts)
	if err != nil {
		t.Fatalf("could not run cuda-tests: %v", err)
	}
	t.Logf("cuda-tests output: %s", string(out))
}
