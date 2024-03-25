// Copyright 2024 The gVisor Authors.
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

// Package imagegen_test runs Stable Diffusion and generates images with it.
package imagegen_test

import (
	"context"
	"testing"
	"time"

	"gvisor.dev/gvisor/test/gpu/stablediffusion"
)

// TestStableDiffusionXL generates an image with Stable Diffusion XL.
func TestStableDiffusionXL(t *testing.T) {
	ctx := context.Background()
	sdxl := stablediffusion.NewDockerXL(t)
	generateCtx, generateCancel := context.WithTimeout(ctx, 15*time.Minute)
	defer generateCancel()
	image, err := sdxl.Generate(generateCtx, &stablediffusion.XLPrompt{
		Query:           `A boring flat corporate logo that says "gVisor"`,
		AllowCPUOffload: false,
		UseRefiner:      false,
		NoiseFraction:   0.8,
		// This is just a test to make sure Stable Diffusion works at all,
		// so we don't need a lot of steps here:
		Steps: 8,
	})
	if err != nil {
		t.Fatalf("Cannot generate image with Stable Diffusion XL: %v", err)
	}
	img, err := image.Image()
	if err != nil {
		t.Fatalf("Cannot decode image: %v", err)
	}
	size := img.Bounds().Size()
	if size.X <= 0 || size.Y <= 0 {
		t.Fatalf("Generated image has invalid size: %dx%d", size.X, size.Y)
	}
	ascii, err := image.ASCII()
	if err != nil {
		t.Fatalf("Cannot convert image to ASCII: %v", err)
	}
	t.Logf("Generated image (size %dx%d pixels):\n%s\n", size.X, size.Y, ascii)
}
