// Copyright 2023 The gVisor Authors.
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

// Package kubectl contains functions to interact with Kubernetes clusters
// controlled using kubectl configurations.
package kubectl

import (
	"fmt"
	"os"
	"os/user"
	"path"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/tools/gvisor_k8s_tool/cluster"
	"k8s.io/client-go/tools/clientcmd"
)

// getKubeConfigPath returns the path to the kubectl config.
func getKubeConfigPath() (string, error) {
	if envPath, ok := os.LookupEnv("KUBECONFIG"); ok {
		return envPath, nil
	}
	me, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("cannot get current user information: %w", err)
	}
	return path.Join(me.HomeDir, ".kube/config"), nil
}

// NewCluster creates a new cluster client for the given context name and
// using the kubectl config defined in the KUBECONFIG environment variable.
// If the context name is empty, the default ("current") context is used.
func NewCluster(contextName string) (*cluster.Cluster, error) {
	cfgPath, err := getKubeConfigPath()
	if err != nil {
		return nil, err
	}
	cfg, err := clientcmd.LoadFromFile(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("cannot load kubectl config at %q: %w", cfgPath, err)
	}
	if contextName == "" {
		contextName = cfg.CurrentContext
		log.Infof("Using default kubectl context: %q", contextName)
	}
	restClient, err := clientcmd.NewNonInteractiveClientConfig(*cfg, contextName, nil, clientcmd.NewDefaultClientConfigLoadingRules()).ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("cannot create REST client: %w", err)
	}
	return cluster.New(restClient)
}
