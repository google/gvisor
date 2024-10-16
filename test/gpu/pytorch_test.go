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

// Package pytorch_test tests basic PyTorch workloads.
package pytorch_test

import (
	"context"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

// runPytorch runs the given script and command in a PyTorch container.
func runPytorch(ctx context.Context, t *testing.T, scriptPath string, args ...string) {
	t.Helper()
	c := dockerutil.MakeContainer(ctx, t)
	opts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{})
	if err != nil {
		t.Fatalf("Failed to get GPU run options: %v", err)
	}
	opts.Image = "gpu/pytorch"
	cmd := append([]string{"python3", scriptPath}, args...)
	out, err := c.Run(ctx, opts, cmd...)
	if err != nil {
		t.Errorf("Failed: %v\nContainer output:\n%s", err, out)
	} else {
		t.Logf("Container output:\n%s", out)
	}
}

// TestCUDAIsAvailable checks that PyTorch recognizes that CUDA is available.
func TestCUDAIsAvailable(t *testing.T) {
	runPytorch(context.Background(), t, "/is_cuda_available.py")
}

// TestLinearRegressionModel runs a simple linear regression model.
func TestLinearRegressionModel(t *testing.T) {
	runPytorch(context.Background(), t, "/pytorch-examples/regression/main.py", "--cuda")
}

// TestMNIST runs an MNIST model.
func TestMNIST(t *testing.T) {
	runPytorch(context.Background(), t, "/pytorch-examples/mnist/main.py", "--epochs=1", "--dry-run")
}

// TestIssue9827 verifies that issue 9827 is fixed.
func TestIssue9827(t *testing.T) {
	// TODO(gvisor.dev/issue/9827): Don't skip this once the
	// test works and doesn't run forever:
	t.Skip("TODO(gvisor.dev/issue/9827): Issue 9827 is not yet fixed.")
	runPytorch(context.Background(), t, "/issue_9827.py")
}
