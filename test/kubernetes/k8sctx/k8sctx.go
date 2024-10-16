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
	"errors"
	"fmt"
	"sync"
	"testing"

	"gvisor.dev/gvisor/test/kubernetes/testcluster"
)

// KubernetesContext represents the Kubernetes execution context.
// It is used to keep track of available Kubernetes clusters to test on.
// Tests are expected to call `RegisterTest` for every of their test function,
// then `TestMain`.
type KubernetesContext interface {
	// TestMain should be called inside tests' `TestMain` function, after having
	// registered all tests with `RegisterTest`.
	TestMain(m *testing.M)

	// RegisterTest registers a test.
	// It should be called for every `Test*(*testing.T)` function in the test.
	// Note that the `k8sctx.TestMain` helper function below will call this for
	// you given a map of tests.
	RegisterTest(name string, fn TestFunc)

	// AcquireCluster returns a single cluster for the test or benchmark to use.
	// The cluster is guaranteed to not be in use by other tests or benchmarks
	// until the `ReleaseCluster` method is called.
	// This method should block if there are no available clusters.
	AcquireCluster(ctx context.Context, t *testing.T) *testcluster.TestCluster

	// ReleaseCluster unlocks the given cluster for use by other tests or
	// benchmarks.
	ReleaseCluster(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster)

	// ForEachCluster reserves as many test clusters as are available, calls
	// `fn` on each of them, and releases each of them when `fn` finishes.
	ForEachCluster(ctx context.Context, t *testing.T, fn func(cluster *testcluster.TestCluster))

	// ResolveImage resolves a container image name (possibly with a label)
	// to a fully-qualified image name. It can also return an `image:label`
	// string if the Kubernetes cluster the test runs in will resolve it on
	// its own.
	ResolveImage(ctx context.Context, imageName string) (string, error)
}

// TestFunc is a test function that is expected to call `Context` and run a
// test or benchmark within a Kubernetes context.
type TestFunc func(t *testing.T)

var (
	kubernetesCtxMu   sync.Mutex
	kubernetesCtxOnce sync.Once
	kubernetesCtxFn   func(context.Context) (KubernetesContext, error)
	kubernetesCtx     KubernetesContext
	kubernetesCtxErr  error
)

// Context gets the global Kubernetes context.
// It must be called after SetContext has already been called.
func Context(ctx context.Context) (KubernetesContext, error) {
	kubernetesCtxMu.Lock()
	defer kubernetesCtxMu.Unlock()
	if kubernetesCtxFn == nil {
		return nil, errors.New("k8sctx.Context called prior to k8sctx.SetContextConstructor")
	}
	kubernetesCtxOnce.Do(func() {
		kubernetesCtx, kubernetesCtxErr = kubernetesCtxFn(ctx)
	})
	return kubernetesCtx, kubernetesCtxErr
}

// SetContextConstructor sets the global Kubernetes context constructor.
func SetContextConstructor(fn func(context.Context) (KubernetesContext, error)) {
	kubernetesCtxMu.Lock()
	defer kubernetesCtxMu.Unlock()
	kubernetesCtxFn = fn
}

// TestMain is a helper to write the TestMain function of tests.
func TestMain(m *testing.M, testFuncs map[string]TestFunc) {
	k8sCtx, err := Context(context.Background())
	if err != nil {
		panic(fmt.Sprintf("failed to get k8sctx: %v", err))
	}
	for name, fn := range testFuncs {
		k8sCtx.RegisterTest(name, fn)
	}
	k8sCtx.TestMain(m)
}
