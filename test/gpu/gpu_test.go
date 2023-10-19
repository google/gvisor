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

// Package cos_gpu_test tests that GPUs work on Container Optimized OS (COS) images in GCP. This
// will probably only work on COS images.
package cos_gpu_test

import (
	"context"
	"testing"

	"github.com/docker/docker/api/types/container"
	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

func TestGPUHello(t *testing.T) {
	ctx := context.Background()
	c := dockerutil.MakeContainer(ctx, t)
	defer c.CleanUp(ctx)

	out, err := c.Run(ctx, dockerutil.RunOpts{
		Image: "basic/cuda-vector-add",
		Devices: []container.DeviceRequest{
			{
				Count:        -1,
				Capabilities: [][]string{[]string{"gpu"}},
				Options:      map[string]string{},
			},
		},
	})

	if err != nil {
		t.Fatalf("could not run nvidia: %v", err)
	}

	t.Logf("nvidia output: %s", string(out))
}
