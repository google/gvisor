// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package ffmpeg_test

import (
	"context"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
)

// TestFffmpegEncodeGPU runs ffmpeg in a GPU container using NVENC.
func TestFffmpegEncodeGPU(t *testing.T) {
	ctx := context.Background()
	container := dockerutil.MakeContainer(ctx, t)
	defer container.CleanUp(ctx)
	opts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{Capabilities: "compute,video"})
	if err != nil {
		t.Fatalf("Failed to get GPU run options: %v", err)
	}
	opts.Image = "benchmarks/ffmpeg"
	cmd := strings.Split("ffmpeg -i video.mp4 -c:v h264_nvenc -preset fast output.mp4", " ")
	if output, err := container.Run(ctx, opts, cmd...); err != nil {
		t.Errorf("failed to run container: %v; output:\n%s", err, output)
	}
}

// TestFffmpegDecodeGPU runs ffmpeg in a GPU container using NVDEC.
func TestFffmpegDecodeGPU(t *testing.T) {
	ctx := context.Background()
	container := dockerutil.MakeContainer(ctx, t)
	defer container.CleanUp(ctx)
	opts, err := dockerutil.GPURunOpts(dockerutil.SniffGPUOpts{Capabilities: "compute,video"})
	if err != nil {
		t.Fatalf("Failed to get GPU run options: %v", err)
	}
	opts.Image = "benchmarks/ffmpeg"
	// h264_cuvid refers to NVDEC. See Section 4.2 in
	// https://docs.nvidia.com/video-technologies/video-codec-sdk/pdf/Using_FFmpeg_with_NVIDIA_GPU_Hardware_Acceleration.pdf
	cmd := strings.Split("ffmpeg -y -vsync 0 -c:v h264_cuvid -i encoded.mp4 output.mp4", " ")
	if output, err := container.Run(ctx, opts, cmd...); err != nil {
		t.Errorf("failed to run container: %v; output:\n%s", err, output)
	}
}
