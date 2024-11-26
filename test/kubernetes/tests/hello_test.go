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

package hello

import (
	"context"
	"testing"

	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
)

// TestHello tests that a trivial alpine container runs correctly.
func TestHello(t *testing.T) {
	ctx := context.Background()
	k8sCtx, err := k8sctx.Context(ctx)
	if err != nil {
		t.Fatalf("Failed to get kubernetes context: %v", err)
	}
	cluster := k8sCtx.AcquireCluster(ctx, t)
	defer k8sCtx.ReleaseCluster(ctx, t, cluster)
	RunHello(ctx, t, k8sCtx, cluster)
}

func TestMain(m *testing.M) {
	k8sctx.TestMain(m, map[string]k8sctx.TestFunc{
		"TestHello": TestHello,
	})
}
