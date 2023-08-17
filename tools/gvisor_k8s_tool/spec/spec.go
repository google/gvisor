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

// Package spec contains Kubernetes object specifications for gVisor setup.
package spec

import (
	"google.golang.org/protobuf/proto"
	appsv1 "k8s.io/api/apps/v1"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	// SystemNamespace is the name of the Kubernetes system namespace.
	SystemNamespace = "kube-system"
	// PauseContainerImage is the name of a container image that does nothing.
	PauseContainerImage = "gcr.io/google-containers/pause"
	// gvisorNodepoolKey the key for the label given to GKE Sandbox nodepools.
	gvisorNodepoolKey = "sandbox.gke.io/runtime"
	// gvisorRuntimeClass the runtimeClassName used for GKE Sandbox pods.
	gvisorRuntimeClass = "gvisor"
)

var (
	// GKESandboxNodeSelector selects GKE Sandbox nodes on GKE.
	GKESandboxNodeSelector = map[string]string{gvisorNodepoolKey: gvisorRuntimeClass}
)

// InstallOptions is the set of options to install runsc.
type InstallOptions struct {
	DaemonSetNamespace  string
	DaemonSetName       string
	Labels              map[string]string
	NodeSelector        map[string]string
	PauseContainerImage string
}

// RunscInstallDaemonSet returns a DaemonSet spec that installs runsc in
// Kubernetes.
func RunscInstallDaemonSet(image string, options InstallOptions) *appsv1.DaemonSet {
	hpType := v13.HostPathDirectory
	return &appsv1.DaemonSet{
		TypeMeta: v1.TypeMeta{
			Kind:       "DaemonSet",
			APIVersion: "apps/v1",
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      options.DaemonSetName,
			Namespace: options.DaemonSetNamespace,
		},
		Spec: appsv1.DaemonSetSpec{
			Selector: &v1.LabelSelector{
				MatchLabels: options.Labels,
			},
			UpdateStrategy: appsv1.DaemonSetUpdateStrategy{
				Type: appsv1.RollingUpdateDaemonSetStrategyType,
			},
			Template: v13.PodTemplateSpec{
				ObjectMeta: v1.ObjectMeta{
					Labels: options.Labels,
				},
				Spec: v13.PodSpec{
					Tolerations: []v13.Toleration{
						{
							Operator: v13.TolerationOpExists,
						},
					},
					HostPID: true,
					InitContainers: []v13.Container{
						{
							Name:  options.DaemonSetName,
							Image: image,
							VolumeMounts: []v13.VolumeMount{
								{
									Name:      "host",
									MountPath: "/host",
								},
							},
							Resources: v13.ResourceRequirements{
								Requests: v13.ResourceList{
									v13.ResourceCPU:    resource.MustParse("5m"),
									v13.ResourceMemory: resource.MustParse("5Mi"),
								},
							},
							SecurityContext: &v13.SecurityContext{
								Capabilities: &v13.Capabilities{
									Add: []v13.Capability{"CAP_SYS_ADMIN"},
								},
								Privileged: proto.Bool(true),
							},
						},
					},
					Containers: []v13.Container{
						{
							Name:  "pause",
							Image: options.PauseContainerImage,
						},
					},
					NodeSelector: options.NodeSelector,
					Volumes: []v13.Volume{
						{
							Name: "host",
							VolumeSource: v13.VolumeSource{
								HostPath: &v13.HostPathVolumeSource{
									Path: "/",
									Type: &hpType,
								},
							},
						},
					},
				},
			},
		},
	}
}
