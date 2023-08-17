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

// Package clusterflag implements a flag.Value which can be used in commands
// to represent a Kubernetes cluster.
package clusterflag

import (
	"context"
	"fmt"
	"strings"

	"gvisor.dev/gvisor/tools/gvisor_k8s_tool/cluster"
	"gvisor.dev/gvisor/tools/gvisor_k8s_tool/provider/gke"
	"gvisor.dev/gvisor/tools/gvisor_k8s_tool/provider/kubectl"
)

// Provider is a cluster provider.
type Provider string

const (
	// Kubectl is a provider using a local kubectl config.
	Kubectl Provider = "kube"

	// GKE is a provider using GKE.
	GKE Provider = "gke"
)

// String returns the provider name.
func (p Provider) String() string {
	return string(p)
}

// Valid returns whether the Provider is valid.
func (p Provider) Valid() bool {
	switch p {
	case Kubectl, GKE:
		return true
	default:
		return false
	}
}

// ValidInfo validates whether the given info is valid for this provider.
func (p Provider) ValidInfo(info string) error {
	switch p {
	case Kubectl:
		return nil
	case GKE:
		_, err := gke.NewClusterURL(info)
		return err
	default:
		return fmt.Errorf("invalid provider: %q", p)
	}
}

// Flag contains the necessary information to connect to a Kubernetes cluster.
// Flag implements flag.Value.
type Flag struct {
	StringVal string
	Provider  Provider
	Info      string
}

// Valid checks if the flag values are valid.
func (f *Flag) Valid() error {
	if !f.Provider.Valid() {
		return fmt.Errorf("invalid provider: %q", f.Provider)
	}
	if err := f.Provider.ValidInfo(f.Info); err != nil {
		return fmt.Errorf("invalid info for provider %q: %w", f.Provider, err)
	}
	return nil
}

// String implements flag.Value.String.
func (f *Flag) String() string {
	return f.StringVal
}

// Get implements flag.Value.Get.
func (f *Flag) Get() any {
	return f
}

// Set implements flag.Value.Set.
// Set(String()) should be idempotent.
func (f *Flag) Set(s string) error {
	f.StringVal = s
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid format: %q (expected <provider>:<info>)", s)
	}
	f2 := Flag{
		StringVal: s,
		Provider:  Provider(parts[0]),
		Info:      parts[1],
	}
	if err := f2.Valid(); err != nil {
		return err
	}
	f.Provider = f2.Provider
	f.Info = f2.Info
	return nil
}

// Cluster creates a cluster client.
func (f *Flag) Cluster(ctx context.Context) (*cluster.Cluster, error) {
	switch f.Provider {
	case Kubectl:
		return kubectl.NewCluster(f.Info)
	case GKE:
		clusterURL, err := gke.NewClusterURL(f.Info)
		if err != nil {
			return nil, err
		}
		return gke.GetCluster(ctx, clusterURL)
	default:
		return nil, fmt.Errorf("invalid provider: %q", f.Provider)
	}
}
