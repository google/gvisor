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
package media

import (
	"context"
	"os"
	"strings"
	"testing"

	"gvisor.dev/gvisor/pkg/test/dockerutil"
	"gvisor.dev/gvisor/test/benchmarks/harness"
)

// BenchmarkFfmpeg runs ffmpeg in a container and records runtime.
// BenchmarkFfmpeg should run as root to drop caches.
func BenchmarkFfmpeg(b *testing.B) {
	machine, err := harness.GetMachine()
	if err != nil {
		b.Fatalf("failed to get machine: %v", err)
	}
	defer machine.CleanUp()

	ctx := context.Background()
	cmd := strings.Split("ffmpeg -i video.mp4 -c:v libx264 -preset veryslow output.mp4", " ")

	b.ResetTimer()
	b.StopTimer()

	for i := 0; i < b.N; i++ {
		container := machine.GetContainer(ctx, b)
		defer container.CleanUp(ctx)
		if err := harness.DropCaches(machine); err != nil {
			b.Skipf("failed to drop caches: %v. You probably need root.", err)
		}

		b.StartTimer()
		if _, err := container.Run(ctx, dockerutil.RunOpts{
			Image: "benchmarks/ffmpeg",
		}, cmd...); err != nil {
			b.Fatalf("failed to run container: %v", err)
		}
		b.StopTimer()
	}
}

func TestMain(m *testing.M) {
	harness.Init()
	os.Exit(m.Run())
}
