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

package pytorch

import (
	"context"
	"testing"

	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx/kubectlctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
)

func TestFastNLPBert(t *testing.T) {
	ctx := context.Background()
	runTests(ctx, t, FastNLPBert)
}

func TestBigBird(t *testing.T) {
	ctx := context.Background()
	runTests(ctx, t, BigBird)
}

func TestSpeechTransformer(t *testing.T) {
	ctx := context.Background()
	runTests(ctx, t, SpeechTransformer)
}

func TestLearningToPaint(t *testing.T) {
	ctx := context.Background()
	runTests(ctx, t, LearningToPaint)
}

func TestMobileNetV2(t *testing.T) {
	ctx := context.Background()
	runTests(ctx, t, MobileNetV2)
}

func runTests(ctx context.Context, t *testing.T, tests []pytorchTest) {
	k8sCtx, err := kubectlctx.New(ctx)
	if err != nil {
		t.Fatalf("Failed to get kubernetes context: %v", err)
	}
	k8sctx.ForEachCluster(ctx, t, k8sCtx, func(cluster *testcluster.TestCluster) {
		t.Run("PyTorch", func(t *testing.T) {
			t.Parallel()
			RunPytorch(ctx, t, k8sCtx, cluster, tests)
		})
	})
}
