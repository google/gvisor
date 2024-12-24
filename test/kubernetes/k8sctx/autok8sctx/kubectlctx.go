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

// Package autok8sctx provides a KubernetesContext that uses a kubectl config
// and context to determine the test cluster to use for tests and benchmarks.
// See parent package (`k8sctx`) for more info.
package autok8sctx

import (
	"context"
	"errors"
	"fmt"

	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	"gvisor.dev/gvisor/tools/gvisor_k8s_tool/provider/kubectl"
)

var (
	kubectlContextName = flag.String("kubectl-context-name", "", "Name of the kubectl context to use within the kubectl config")
)

// New creates a KubernetesContext using flags to determine which kubectl
// config and kubectl context to use as the test cluster.
func New(ctx context.Context) (k8sctx.KubernetesContext, error) {
	if *kubectlContextName == "" {
		return nil, errors.New("no kubectl context name specified")
	}
	cluster, err := kubectl.NewCluster(*kubectlContextName)
	if err != nil {
		return nil, fmt.Errorf("cannot initialize cluster %q: %w", *kubectlContextName, err)
	}
	testCluster := testcluster.NewTestClusterFromClient(*kubectlContextName, cluster.Client())
	return k8sctx.NewSingleCluster(testCluster), nil
}
