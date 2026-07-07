// Copyright 2026 The gVisor Authors.
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

package testcluster

import (
	"strings"
	"testing"

	v23 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestGetPersistentVolume(t *testing.T) {
	ns := &Namespace{
		Namespace: "test-ns",
	}

	testCases := []struct {
		name string
		size string
	}{
		{
			name: "test-pv-1",
			size: "1Gi",
		},
		{
			name: "test-pv-2",
			size: "10Gi",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pvc := ns.GetPersistentVolume(tc.name, tc.size)

			if pvc.ObjectMeta.Name != tc.name {
				t.Errorf("expected name %q, got %q", tc.name, pvc.ObjectMeta.Name)
			}

			if pvc.ObjectMeta.Namespace != ns.Namespace {
				t.Errorf("expected namespace %q, got %q", ns.Namespace, pvc.ObjectMeta.Namespace)
			}

			// Verify size.
			verifyResource(t, pvc.Spec.Resources.Requests, v23.ResourceStorage, tc.size)
		})
	}
}

func TestSetContainerResources(t *testing.T) {
	testCases := []struct {
		name          string
		pod           *v23.Pod
		containerName string
		requests      ContainerResourcesRequest
		wantErr       string
		wantPod       func(t *testing.T, got *v23.Pod)
	}{
		{
			name: "empty container name, single container, empty requests",
			pod: &v23.Pod{
				Spec: v23.PodSpec{
					Containers: []v23.Container{
						{
							Name: "container-1",
							Resources: v23.ResourceRequirements{
								Limits:   v23.ResourceList{},
								Requests: v23.ResourceList{},
							},
						},
					},
				},
			},
			containerName: "",
			requests:      ContainerResourcesRequest{},
			wantPod: func(t *testing.T, got *v23.Pod) {
				if got == nil {
					t.Fatal("got nil pod")
				}
				if len(got.Spec.Containers) != 1 {
					t.Fatalf("expected 1 container, got %d", len(got.Spec.Containers))
				}
				c := got.Spec.Containers[0]
				if len(c.Resources.Limits) != 0 || len(c.Resources.Requests) != 0 {
					t.Errorf("expected no resources set, got limits: %v, requests: %v", c.Resources.Limits, c.Resources.Requests)
				}
			},
		},
		{
			name: "empty container name, multiple containers",
			pod: &v23.Pod{
				Spec: v23.PodSpec{
					Containers: []v23.Container{
						{Name: "container-1"},
						{Name: "container-2"},
					},
				},
			},
			containerName: "",
			requests:      ContainerResourcesRequest{},
			wantErr:       "multiple containers found in pod",
		},
		{
			name: "empty container name, no containers",
			pod: &v23.Pod{
				Spec: v23.PodSpec{
					Containers: []v23.Container{},
				},
			},
			containerName: "",
			requests:      ContainerResourcesRequest{},
			wantErr:       "no containers found in pod",
		},
		{
			name: "non-empty container name, selects correct container",
			pod: &v23.Pod{
				Spec: v23.PodSpec{
					Containers: []v23.Container{
						{
							Name: "container-1",
							Resources: v23.ResourceRequirements{
								Limits:   v23.ResourceList{},
								Requests: v23.ResourceList{},
							},
						},
						{
							Name: "container-2",
							Resources: v23.ResourceRequirements{
								Limits:   v23.ResourceList{},
								Requests: v23.ResourceList{},
							},
						},
					},
				},
			},
			containerName: "container-2",
			requests:      ContainerResourcesRequest{},
			wantPod: func(t *testing.T, got *v23.Pod) {
				if got == nil {
					t.Fatal("got nil pod")
				}
				if got.Spec.Containers[0].Name != "container-1" || got.Spec.Containers[1].Name != "container-2" {
					t.Errorf("unexpected container order")
				}
			},
		},
		{
			name: "container name not found",
			pod: &v23.Pod{
				Spec: v23.PodSpec{
					Containers: []v23.Container{
						{Name: "container-1"},
					},
				},
			},
			containerName: "container-2",
			requests:      ContainerResourcesRequest{},
			wantErr:       `container "container-2" not found`,
		},
		{
			name: "GPU request without node selector",
			pod: &v23.Pod{
				Spec: v23.PodSpec{
					Containers: []v23.Container{
						{
							Name: "container-1",
							Resources: v23.ResourceRequirements{
								Limits:   v23.ResourceList{},
								Requests: v23.ResourceList{},
							},
						},
					},
				},
			},
			containerName: "",
			requests: ContainerResourcesRequest{
				GPU: true,
			},
			wantErr: "cannot determine number of accelerators",
		},
		{
			name: "TPU request without node selector",
			pod: &v23.Pod{
				Spec: v23.PodSpec{
					Containers: []v23.Container{
						{
							Name: "container-1",
							Resources: v23.ResourceRequirements{
								Limits:   v23.ResourceList{},
								Requests: v23.ResourceList{},
							},
						},
					},
				},
			},
			containerName: "",
			requests: ContainerResourcesRequest{
				TPU: true,
			},
			wantErr: "cannot determine number of accelerators",
		},
		{
			name: "GPU request with node selector key",
			pod: &v23.Pod{
				Spec: v23.PodSpec{
					NodeSelector: map[string]string{
						"num-accelerators": "4",
					},
					Containers: []v23.Container{
						{
							Name: "container-1",
							Resources: v23.ResourceRequirements{
								Limits:   v23.ResourceList{},
								Requests: v23.ResourceList{},
							},
						},
					},
				},
			},
			containerName: "",
			requests: ContainerResourcesRequest{
				GPU: true,
			},
			wantPod: func(t *testing.T, got *v23.Pod) {
				if got == nil {
					t.Fatal("got nil pod")
				}
				c := got.Spec.Containers[0]
				verifyResource(t, c.Resources.Limits, "nvidia.com/gpu", "4")
				verifyResource(t, c.Resources.Requests, "nvidia.com/gpu", "4")
			},
		},
		{
			name: "TPU request with node selector key",
			pod: &v23.Pod{
				Spec: v23.PodSpec{
					NodeSelector: map[string]string{
						"cloud.google.com/gke-accelerator-count": "8",
					},
					Containers: []v23.Container{
						{
							Name: "container-1",
							Resources: v23.ResourceRequirements{
								Limits:   v23.ResourceList{},
								Requests: v23.ResourceList{},
							},
						},
					},
				},
			},
			containerName: "",
			requests: ContainerResourcesRequest{
				TPU: true,
			},
			wantPod: func(t *testing.T, got *v23.Pod) {
				if got == nil {
					t.Fatal("got nil pod")
				}
				c := got.Spec.Containers[0]
				verifyResource(t, c.Resources.Limits, "google.com/tpu", "8")
				verifyResource(t, c.Resources.Requests, "google.com/tpu", "8")
			},
		},
		{
			name: "preserves existing CPU and memory limits and requests",
			pod: &v23.Pod{
				Spec: v23.PodSpec{
					NodeSelector: map[string]string{
						"num-accelerators": "4",
					},
					Containers: []v23.Container{
						{
							Name: "container-1",
							Resources: v23.ResourceRequirements{
								Limits: v23.ResourceList{
									v23.ResourceCPU:    resource.MustParse("1"),
									v23.ResourceMemory: resource.MustParse("2Gi"),
								},
								Requests: v23.ResourceList{
									v23.ResourceCPU:    resource.MustParse("500m"),
									v23.ResourceMemory: resource.MustParse("1Gi"),
								},
							},
						},
					},
				},
			},
			containerName: "",
			requests: ContainerResourcesRequest{
				GPU: true,
			},
			wantPod: func(t *testing.T, got *v23.Pod) {
				if got == nil {
					t.Fatal("got nil pod")
				}
				c := got.Spec.Containers[0]
				// Verify CPU and Memory are preserved.
				verifyResource(t, c.Resources.Limits, v23.ResourceCPU, "1")
				verifyResource(t, c.Resources.Limits, v23.ResourceMemory, "2Gi")
				verifyResource(t, c.Resources.Requests, v23.ResourceCPU, "500m")
				verifyResource(t, c.Resources.Requests, v23.ResourceMemory, "1Gi")
			},
		},
		{
			name: "handles nil Limits and Requests maps",
			pod: &v23.Pod{
				Spec: v23.PodSpec{
					NodeSelector: map[string]string{
						"num-accelerators": "4",
					},
					Containers: []v23.Container{
						{
							Name: "container-1",
							Resources: v23.ResourceRequirements{
								Limits:   nil,
								Requests: nil,
							},
						},
					},
				},
			},
			containerName: "",
			requests: ContainerResourcesRequest{
				GPU: true,
			},
			wantPod: func(t *testing.T, got *v23.Pod) {
				if got == nil {
					t.Fatal("got nil pod")
				}
				c := got.Spec.Containers[0]
				verifyResource(t, c.Resources.Limits, "nvidia.com/gpu", "4")
				verifyResource(t, c.Resources.Requests, "nvidia.com/gpu", "4")
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SetContainerResources(tc.pod, tc.containerName, tc.requests)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantPod != nil {
				tc.wantPod(t, got)
			}
		})
	}
}

func verifyResource(t *testing.T, list v23.ResourceList, name v23.ResourceName, want string) {
	t.Helper()
	if list == nil {
		t.Errorf("resource list is nil, expected resource %q to be %q", name, want)
		return
	}
	qty, ok := list[name]
	if !ok {
		t.Errorf("expected resource %q to be set", name)
		return
	}
	expected := resource.MustParse(want)
	if !qty.Equal(expected) {
		t.Errorf("expected resource %q to be %v, got %v", name, expected, qty)
	}
}
