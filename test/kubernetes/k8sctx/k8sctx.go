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

// Package k8sctx is used to manage the lifecycle of a Kubernetes test or
// benchmark running in one or more Kubernetes clusters.
// It is used to control the behavior of Kubernetes-based tests and benchmarks
// at runtime and to abstract away how the Kubernetes test clusters are
// created and managed from the test code.
package k8sctx

import (
	"context"
	"sync"
	"testing"

	"gvisor.dev/gvisor/test/kubernetes/testcluster"
)

// KubernetesContext represents the Kubernetes execution context.
// It is used to keep track of available Kubernetes clusters to test on.
// Tests are expected to call `RegisterTest` for every of their test function,
// then `TestMain`.
type KubernetesContext interface {
	// Cluster returns a single cluster for the test or benchmark to use.
	// The cluster is guaranteed to not be in use by other tests or benchmarks
	// until the returned function is called.
	// If there are no available clusters, it returns a nil TestCluster.
	Cluster(ctx context.Context, t *testing.T) (*testcluster.TestCluster, func())

	// ResolveImage resolves a container image name (possibly with a label)
	// to a fully-qualified image name. It can also return an `image:label`
	// string if the Kubernetes cluster the test runs in will resolve it on
	// its own.
	ResolveImage(ctx context.Context, imageName string) (string, error)
}

// ForEachCluster calls the given function for each available cluster
// sequentially.
// In order to run per-cluster subtests in parallel, call `t.Run` inside
// `fn` and then `t.Parallel` inside that.
func ForEachCluster(ctx context.Context, t *testing.T, k8sCtx KubernetesContext, fn func(cluster *testcluster.TestCluster)) {
	var clusterFns []func()
	for {
		cluster, releaseFn := k8sCtx.Cluster(ctx, t)
		if cluster == nil {
			break
		}
		clusterFns = append(clusterFns, func() {
			defer releaseFn()
			fn(cluster)
		})
	}
	for _, clusterFn := range clusterFns {
		clusterFn()
	}
}

// singleCluster implements KubernetesContext using a single cluster.
type singleCluster struct {
	mu      sync.Mutex
	cluster *testcluster.TestCluster
}

// Cluster implements KubernetesContext.Cluster.
func (sc *singleCluster) Cluster(ctx context.Context, t *testing.T) (*testcluster.TestCluster, func()) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	cl := sc.cluster
	sc.cluster = nil
	return cl, func() {
		if cl != nil {
			sc.mu.Lock()
			defer sc.mu.Unlock()
			sc.cluster = cl
		}
	}
}

// ResolveImage implements KubernetesContext.ResolveImage.
func (*singleCluster) ResolveImage(ctx context.Context, imageName string) (string, error) {
	return imageName, nil
}

// NewSingleCluster creates a KubernetesContext that uses a single, static
// test cluster.
func NewSingleCluster(cluster *testcluster.TestCluster) KubernetesContext {
	return &singleCluster{cluster: cluster}
}
