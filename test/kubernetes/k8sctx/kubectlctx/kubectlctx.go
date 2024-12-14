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

// Package kubectlctx provides a KubernetesContext that uses one or more
// kubectl configs to determine the cluster(s) to use for tests and benchmarks.
// See parent package (`k8sctx`) for more info.
package kubectlctx

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sync/errgroup"
	"google.golang.org/protobuf/encoding/prototext"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	testpb "gvisor.dev/gvisor/test/kubernetes/test_range_config_go_proto"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	"gvisor.dev/gvisor/tools/gvisor_k8s_tool/provider/kubectl"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	rangeDir            = flag.String("range-dir", "", "A directory containing a test_range.textproto text file describing multiple clusters to use for tests and benchmarks; takes precedence over --kubectl-context-name")
	kubectlContext      = flag.String("kubectl-context", "", "The name of the kubectl context to use; if unset, use the default context within the kubectl config at KUBECONFIG")
	testNodepoolRuntime = flag.String("test-nodepool-runtime", "", "if set, override the runtime used for pods scheduled on the 'test' nodepool. If unset, the nodepool default is used")
)

// New creates a KubernetesContext using flags to determine which clusters
// to use for tests and benchmarks.
func New(ctx context.Context) (k8sctx.KubernetesContext, error) {
	if *rangeDir != "" && *kubectlContext != "" {
		return nil, fmt.Errorf("cannot use --range-dir and --kubectl-context at the same time")
	}
	var clusters []*testcluster.TestCluster
	var err error
	if *rangeDir != "" {
		clusters, err = NewFromRangeDir(ctx, *rangeDir)
	} else {
		clusters, err = NewFromKubectlContext(ctx, *kubectlContext)
	}
	if err != nil {
		return nil, fmt.Errorf("cannot initialize test clusters: %w", err)
	}
	if *testNodepoolRuntime != "" {
		overriddenRuntime := testcluster.RuntimeType(*testNodepoolRuntime)
		if !overriddenRuntime.IsValid() {
			return nil, fmt.Errorf("invalid runtime type %q", *testNodepoolRuntime)
		}
		for _, cluster := range clusters {
			cluster.OverrideTestNodepoolRuntime(overriddenRuntime)
		}
	}
	if err := verifyClusters(ctx, clusters); err != nil {
		return nil, fmt.Errorf("cannot verify clusters are working: %w", err)
	}
	return k8sctx.New(clusters...), nil
}

// NewFromRangeDir creates a set of test clusters from a test range directory.
func NewFromRangeDir(ctx context.Context, rangeDir string) ([]*testcluster.TestCluster, error) {
	rangeFile := filepath.Join(rangeDir, "test_range.textproto")
	rangeFileData, err := os.ReadFile(rangeFile)
	if err != nil {
		return nil, fmt.Errorf("cannot read range file %q: %w", rangeFile, err)
	}
	var testRange testpb.TestRange
	if err := prototext.Unmarshal(rangeFileData, &testRange); err != nil {
		return nil, fmt.Errorf("error unmarshalling range file %q: %v", rangeFile, err)
	}
	if len(testRange.GetClusters()) == 0 {
		return nil, fmt.Errorf("range file %q has no clusters", rangeFile)
	}
	clusters := make([]*testcluster.TestCluster, len(testRange.GetClusters()))
	for i, cluster := range testRange.GetClusters() {
		configPath := cluster.GetKubectlConfig()
		if configPath == "" {
			return nil, fmt.Errorf("cluster %q has no kubectl config path", cluster.GetCluster())
		}
		cfg, err := clientcmd.LoadFromFile(configPath)
		if err != nil {
			return nil, fmt.Errorf("cannot load kubectl config at %q for cluster %q: %w", configPath, cluster.GetCluster(), err)
		}
		contextName := cluster.GetKubectlContext()
		if contextName == "" {
			contextName = cfg.CurrentContext
		}
		restConfig, err := clientcmd.NewNonInteractiveClientConfig(*cfg, contextName, nil, clientcmd.NewDefaultClientConfigLoadingRules()).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("cannot load REST client config for cluster %q: %w", cluster.GetCluster(), err)
		}
		kubeClient, err := kubernetes.NewForConfig(restConfig)
		if err != nil {
			return nil, fmt.Errorf("cannot create Kubernetes client for cluster %q: %w", cluster.GetCluster(), err)
		}
		clusters[i] = testcluster.NewTestClusterFromClient(cluster.GetCluster(), kubeClient)
	}
	return clusters, nil
}

// NewFromKubectlContext creates a test cluster from a kubectl config.
//
// If the kubectl config is not specified, the default kubectl config is used.
// If the kubectl context is not specified, the default context within the
// kubectl config is used.
func NewFromKubectlContext(ctx context.Context, kubectlContext string) ([]*testcluster.TestCluster, error) {
	cluster, err := kubectl.NewCluster(kubectlContext)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize cluster from kubectl config: %w", err)
	}
	clusterName := "test-cluster" // Default name.
	if kubectlContext != "" {
		clusterName = kubectlContext
	}
	return []*testcluster.TestCluster{testcluster.NewTestClusterFromClient(clusterName, cluster.Client())}, nil
}

// verifyClusters verifies that all clusters are working.
func verifyClusters(ctx context.Context, clusters []*testcluster.TestCluster) error {
	var g errgroup.Group
	for _, cluster := range clusters {
		c := cluster
		g.Go(func() error {
			return c.SanityCheck(ctx)
		})
	}
	return g.Wait()
}
