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

// Package gke contains functions to interact with Google Kubernetes Engine.
package gke

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path"
	"strings"

	"gvisor.dev/gvisor/tools/gvisor_k8s_tool/cluster"
	"gvisor.dev/gvisor/tools/gvisor_k8s_tool/util"
	"k8s.io/client-go/tools/clientcmd"
)

// ClusterURL represents a GKE cluster URL of the format:
// "projects/$MYPROJECT/locations/$CONTINENT-$LOCATION/clusters/$CLUSTER"
type ClusterURL struct {
	ProjectID   string
	Location    string
	ClusterName string
}

// String returns the cluster URL string.
func (c ClusterURL) String() string {
	return fmt.Sprintf("projects/%s/locations/%s/clusters/%s", c.ProjectID, c.Location, c.ClusterName)
}

// NewClusterURL parses the cluster URL.
func NewClusterURL(url string) (ClusterURL, error) {
	if !strings.HasPrefix(url, "projects/") {
		return ClusterURL{}, fmt.Errorf("invalid GKE cluster URL (expecting 'projects/MYPROJECT/locations/LOCATION/clusters/MYCLUSTER'): %q", url)
	}
	parts := strings.Split(url, "/")
	if len(parts) != 6 {
		return ClusterURL{}, fmt.Errorf("invalid GKE cluster URL (expecting 6 slash-delimited parts, got %d): %q", len(parts), url)
	}
	if parts[0] != "projects" || parts[2] != "locations" || parts[4] != "clusters" {
		return ClusterURL{}, fmt.Errorf("invalid GKE cluster URL (expecting 'projects/MYPROJECT/locations/LOCATION/clusters/MYCLUSTER'): %q", url)
	}
	return ClusterURL{
		ProjectID:   parts[1],
		Location:    parts[3],
		ClusterName: parts[5],
	}, nil
}

// GetCluster returns a Kubernetes client for the given named cluster.
func GetCluster(ctx context.Context, clusterURL ClusterURL) (*cluster.Cluster, error) {
	tmpDir, cleanTmp, err := util.TempDir()
	defer cleanTmp()
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	credFilePath := path.Join(tmpDir, fmt.Sprintf("%s.credential", clusterURL.ClusterName))
	f, err := os.Create(credFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to create cred file: %v", err)
	}
	f.Close()
	cmd := exec.CommandContext(ctx, "gcloud", "--project", clusterURL.ProjectID, "container", "clusters", "get-credentials", clusterURL.ClusterName, "--location", clusterURL.Location)
	cmd.Env = append(cmd.Environ(), fmt.Sprintf("KUBECONFIG=%s", credFilePath))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to set credentials: %v; output: %s", err, string(out))
	}
	configBytes, err := os.ReadFile(credFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read kubectl config file: %w", err)
	}
	kubeCfg, err := clientcmd.RESTConfigFromKubeConfig(configBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubectl config file: %w", err)
	}
	gkeCluster, err := cluster.New(kubeCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate GKE cluster client: %w", err)
	}
	return gkeCluster, nil
}
