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

//go:build !false
// +build !false

package k8sctx

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	cspb "cloud.google.com/go/container/apiv1/containerpb"
	"google.golang.org/protobuf/encoding/prototext"
	"gvisor.dev/gvisor/runsc/flag"
	testpb "gvisor.dev/gvisor/test/kubernetes/test_range_config_go_proto"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	"gvisor.dev/gvisor/tools/gvisor_k8s_tool/provider/kubectl"
)

var (
	kubectlContextName  = flag.String("kubectl-context-name", "", "Name of the kubectl context to use within the kubectl config")
	clusterProtoPath    = flag.String("cluter-proto-path", "", "Path to a `google.container.v1.Cluster` textproto file")
	testNodepoolRuntime = flag.String("test-nodepool-runtime", "", "if set, override the runtime used for pods scheduled on the 'test' nodepool. If unset, the nodepool default is used")
)

// kubectlContext implements KubernetesContext using a named `kubectl` context
// from the user's kubectl config.
type kubectlContext struct {
	cluster *testcluster.TestCluster
}

func newKubectlContext(ctx context.Context) (KubernetesContext, error) {
	if *kubectlContextName == "" {
		return nil, errors.New("no kubectl context name specified")
	}
	if *clusterProtoPath == "" {
		return nil, errors.New("no cluster proto path specified")
	}
	cluster, err := kubectl.NewCluster(*kubectlContextName)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize cluster %q: %w", *kubectlContextName, err)
	}
	var clusterPB cspb.Cluster
	clusterBytes, err := os.ReadFile(*clusterProtoPath)
	if err != nil {
		return nil, fmt.Errorf("cannot read cluster textproto file %q: %w", *clusterProtoPath, err)
	}
	if err = prototext.Unmarshal(clusterBytes, &clusterPB); err != nil {
		return nil, fmt.Errorf("cannot unmarshal cluster textproto file %q: %w", *clusterProtoPath, err)
	}
	testCluster := testcluster.NewTestClusterWithClient(&testpb.Cluster{Cluster: &clusterPB}, cluster.Client())
	if *testNodepoolRuntime != "" {
		testCluster.OverrideTestNodepoolRuntime(testcluster.RuntimeType(*testNodepoolRuntime))
	}
	return &kubectlContext{cluster: testCluster}, nil
}

func (c *kubectlContext) AcquireCluster(ctx context.Context, t *testing.T) *testcluster.TestCluster {
	return c.cluster
}

func (c *kubectlContext) ReleaseCluster(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster) {
	// Nothing to do.
}

func (c *kubectlContext) ForEachCluster(ctx context.Context, t *testing.T, fn func(cluster *testcluster.TestCluster)) {
	fn(c.cluster)
}

func (c *kubectlContext) ResolveImage(ctx context.Context, imageName string) (string, error) {
	return imageName, nil
}

func (c *kubectlContext) RegisterTest(name string, fn TestFunc) {
	// Nothing to do here, we use the regular testing library.
}

func (c *kubectlContext) TestMain(m *testing.M) {
	os.Exit(m.Run())
}

func init() {
	SetContextConstructor(newKubectlContext)
}
