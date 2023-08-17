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

// Package cluster provides functions for dealing with Kubernetes clusters.
package cluster

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	// NamespaceDefault is the name of the default Kubernetes namespace.
	NamespaceDefault = "default"
)

// Cluster presents Kubernetes API method over a Kubernetes cluster.
type Cluster struct {
	client kubernetes.Interface
}

// New initializes a new Cluster from the given client REST config.
func New(config *rest.Config) (*Cluster, error) {
	clientSet, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("kubernetes.NewForConfig: %w", err)
	}
	return &Cluster{clientSet}, nil
}

// CreateDaemonset creates a daemonset with default options.
func (c *Cluster) CreateDaemonset(ctx context.Context, ds *appsv1.DaemonSet) (*appsv1.DaemonSet, error) {
	if ds.GetObjectMeta().GetNamespace() == "" {
		ds.SetNamespace(NamespaceDefault)
	}
	return c.client.AppsV1().DaemonSets(ds.GetNamespace()).Create(ctx, ds, v1.CreateOptions{})
}

// DeleteDaemonset deletes a daemonset from this cluster.
func (c *Cluster) DeleteDaemonset(ctx context.Context, ds *appsv1.DaemonSet) error {
	return c.client.AppsV1().DaemonSets(ds.GetNamespace()).Delete(ctx, ds.GetName(), v1.DeleteOptions{})
}

// WaitForDaemonset waits until a daemonset has propagated containers across the affected nodes.
func (c *Cluster) WaitForDaemonset(ctx context.Context, ds *appsv1.DaemonSet) error {
	w, err := c.client.AppsV1().DaemonSets(ds.GetNamespace()).Watch(ctx, v1.ListOptions{
		FieldSelector: fields.SelectorFromSet(fields.Set{v1.ObjectNameField: ds.ObjectMeta.Name}).String(),
	})

	if err != nil {
		return fmt.Errorf("failed to watch DaemonSet: %w", err)
	}
	defer w.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context canceled before DaemonSet was healthy")
		case e, ok := <-w.ResultChan():
			d, ok := e.Object.(*appsv1.DaemonSet)
			if !ok {
				return fmt.Errorf("invalid object type: %T", d)
			}
			if d.Status.NumberReady == d.Status.DesiredNumberScheduled && d.Status.NumberUnavailable == 0 {
				return nil
			}
		}
	}
}
