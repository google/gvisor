// Copyright 2026 The gVisor Authors.
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

package openclaw

import (
	"context"
	"testing"

	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx/kubectlctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
)

func TestOpenClaw(t *testing.T) {
	ctx := context.Background()
	k8sCtx, err := kubectlctx.New(ctx)
	if err != nil {
		t.Fatalf("Failed to get kubernetes context: %v", err)
	}
	k8sctx.ForEachCluster(ctx, t, k8sCtx, func(cluster *testcluster.TestCluster) {
		t.Run("openclaw", func(t *testing.T) {
			t.Parallel()
			RunOpenClaw(ctx, t, k8sCtx, cluster)
		})
	})
}

func TestNextAdaptiveBatchSize(t *testing.T) {
	// Test 2x scaling: plenty of room
	bSize, canInc := nextAdaptiveBatchSize(1, 1, 256, 100*1024*1024*1024, 128*1024*1024*1024, 1500*1024*1024, true)
	if bSize != 2 || !canInc {
		t.Errorf("Expected (2, true), got (%d, %t)", bSize, canInc)
	}

	// Test 1x keep when 2x would exceed headroom
	// Suppose memAvail allows 2 pods (3 GiB) but not 4 pods (6 GiB)
	bSize, canInc = nextAdaptiveBatchSize(2, 10, 256, 10*1024*1024*1024, 100*1024*1024*1024, 15*1024*1024*1024, true)
	if bSize != 2 || !canInc {
		t.Errorf("Expected (2, true), got (%d, %t)", bSize, canInc)
	}

	// Test fallback to 1 and disabling further increases when headroom is low
	bSize, canInc = nextAdaptiveBatchSize(4, 100, 256, 1*1024*1024*1024, 100*1024*1024*1024, 150*1024*1024*1024, true)
	if bSize != 1 || canInc {
		t.Errorf("Expected (1, false), got (%d, %t)", bSize, canInc)
	}
}
