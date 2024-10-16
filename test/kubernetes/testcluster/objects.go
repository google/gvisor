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

package testcluster

import (
	"context"
	"fmt"
	"strconv"

	cspb "cloud.google.com/go/container/apiv1/containerpb"
	"google.golang.org/protobuf/proto"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	pod   = "Pod"
	apiV1 = "v1"
)

// Namespace represents a Kubernetes object namespace.
// It can contain pods or services or other Kubernetes objects.
// It is useful in tests that create multiple objects and want to ensure
// their mutual destruction, as well as for re-running tests and ensuring
// that the objects from past runs are cleaned up properly on the next run.
type Namespace struct {
	testCluster *TestCluster
	Namespace   string
}

// Namespace returns a new namespace in this cluster.
func (t *TestCluster) Namespace(namespace string) *Namespace {
	return &Namespace{
		testCluster: t,
		Namespace:   namespace,
	}
}

// Reset deletes this namespace if it exists, and unconditionally
// creates a new namespace of this name.
// This should be used in the beginning of tests, such that the namespace
// is empty and ready to be used.
func (n *Namespace) Reset(ctx context.Context) error {
	n.Cleanup(ctx)
	_, err := n.testCluster.createNamespace(ctx, &v13.Namespace{
		TypeMeta: v1.TypeMeta{
			Kind:       "namespace",
			APIVersion: apiV1,
		},
		ObjectMeta: v1.ObjectMeta{
			Name: n.Namespace,
		},
	})
	return err
}

// Cleanup deletes this namespace if it exists.
func (n *Namespace) Cleanup(ctx context.Context) error {
	return n.testCluster.deleteNamespace(ctx, n.Namespace)
}

// NewAlpinePod returns an alpine pod template.
func (n *Namespace) NewAlpinePod(name, image string, cmd []string) *v13.Pod {
	container := v13.Container{Name: name, Image: image, Command: cmd}
	pod := n.NewPod(name)
	pod.Spec.Containers = []v13.Container{container}
	return pod
}

// NewPod returns a pod template.
func (n *Namespace) NewPod(name string) *v13.Pod {
	return &v13.Pod{
		TypeMeta: v1.TypeMeta{
			Kind:       pod,
			APIVersion: apiV1,
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: n.Namespace,
		},
		Spec: v13.PodSpec{
			RestartPolicy: v13.RestartPolicyNever,
		},
	}
}

// GetPersistentVolume gets a persistent volume spec for benchmarks.
func (n *Namespace) GetPersistentVolume(name, size string) *v13.PersistentVolumeClaim {
	return &v13.PersistentVolumeClaim{
		TypeMeta: v1.TypeMeta{
			Kind:       "PersistentVolumeClaim",
			APIVersion: apiV1,
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: n.Namespace,
		},
		Spec: v13.PersistentVolumeClaimSpec{
			AccessModes: []v13.PersistentVolumeAccessMode{v13.ReadWriteOnce},
			Resources: v13.ResourceRequirements{
				Requests: v13.ResourceList{
					v13.ResourceStorage: resource.MustParse(size),
				},
			},
		},
	}
}

// GetService gets a service spec for benchmarks.
func (n *Namespace) GetService(name string, spec v13.ServiceSpec) *v13.Service {
	return &v13.Service{
		TypeMeta: v1.TypeMeta{
			Kind:       "Service",
			APIVersion: apiV1,
		},
		ObjectMeta: v1.ObjectMeta{
			Name:      name,
			Namespace: n.Namespace,
		},
		Spec: spec,
	}
}

// ContainerResourcesRequest holds arguments to set requested resource on a container.
type ContainerResourcesRequest struct {
	CPUResources    string // CPUResources to request. Note: Will be overridden by flag above.
	MemoryResources string // MemoryResources to request. Note: Will be overridden by flag above.
	GPU             bool
}

// MaybeSetContainerResources sets container resources if flags are given. Sets both the resource
// limits and requests as container runtimes honor them differently.
func MaybeSetContainerResources(pod *v13.Pod, containerName string, requests ContainerResourcesRequest) (*v13.Pod, error) {
	resourceList := v13.ResourceList{}
	if requests.CPUResources != "" {
		resourceList[v13.ResourceCPU] = resource.MustParse(requests.CPUResources)
	}
	if requests.MemoryResources != "" {
		resourceList[v13.ResourceMemory] = resource.MustParse(requests.MemoryResources)
	}

	if requests.GPU {
		acceleratorCount, ok := pod.Spec.NodeSelector[NodepoolNumAcceleratorsKey]
		if !ok {
			return nil, fmt.Errorf("cannot determine number of accelerators that the pod should use, make sure to call ConfigurePodForRuntimeTestNodepool first")
		}
		resourceList[v13.ResourceName("nvidia.com/gpu")] = resource.MustParse(acceleratorCount)
	}

	requirements := v13.ResourceRequirements{
		Limits:   resourceList,
		Requests: resourceList,
	}

	for i := range pod.Spec.Containers {
		if pod.Spec.Containers[i].Name == containerName {
			pod.Spec.Containers[i].Resources = requirements
			return pod, nil
		}
	}
	return nil, fmt.Errorf("container %q not found", containerName)
}

// RuntimeType is a supported runtime for the test nodepool.
type RuntimeType string

// List of known runtime types.
const (
	RuntimeTypeGVisor            = RuntimeType("gvisor")
	RuntimeTypeUnsandboxed       = RuntimeType("runc")
	RuntimeTypeGVisorNvidia      = RuntimeType("gvisor-nvidia")
	RuntimeTypeGVisorTPU         = RuntimeType("gvisor-tpu")
	RuntimeTypeUnsandboxedNvidia = RuntimeType("runc-nvidia")
	RuntimeTypeUnsandboxedTPU    = RuntimeType("runc-tpu")
)

// ApplyNodepool modifies the nodepool to configure it to use the runtime.
func (t RuntimeType) ApplyNodepool(nodepool *cspb.NodePool, accelType AcceleratorType, accelShape string, accelRes string) {
	if nodepool.GetConfig().GetLabels() == nil {
		nodepool.GetConfig().Labels = map[string]string{}
	}

	switch t {
	case RuntimeTypeGVisor:
		nodepool.Config.SandboxConfig = &cspb.SandboxConfig{
			Type: cspb.SandboxConfig_GVISOR,
		}
		nodepool.GetConfig().Labels[NodepoolRuntimeKey] = string(RuntimeTypeGVisor)
	case RuntimeTypeUnsandboxed:
		nodepool.GetConfig().Labels[NodepoolRuntimeKey] = string(RuntimeTypeUnsandboxed)
		// Do nothing.
	case RuntimeTypeGVisorNvidia:
		nodepool.Config.SandboxConfig = &cspb.SandboxConfig{
			Type: cspb.SandboxConfig_GVISOR,
		}
		accelCount, err := strconv.Atoi(accelShape)
		if err != nil {
			panic(fmt.Sprintf("GPU count must be a valid number, got %v", accelShape))
		}
		if accelCount == 0 {
			panic("GPU count needs to be >=1")
		}
		nodepool.Config.MachineType = DefaultNvidiaMachineType
		nodepool.Config.Accelerators = []*cspb.AcceleratorConfig{
			{
				AcceleratorType:  string(accelType),
				AcceleratorCount: int64(accelCount),
			},
		}
		nodepool.Config.Labels[NodepoolRuntimeKey] = string(RuntimeTypeGVisorNvidia)
		nodepool.Config.Labels[NodepoolNumAcceleratorsKey] = strconv.Itoa(accelCount)
	case RuntimeTypeGVisorTPU:
		nodepool.Config.MachineType = TPUAcceleratorMachineTypeMap[accelType]
		nodepool.PlacementPolicy = &cspb.NodePool_PlacementPolicy{
			TpuTopology: accelShape,
			Type:        cspb.NodePool_PlacementPolicy_COMPACT,
		}

		nodepool.Config.Labels[gvisorNodepoolKey] = gvisorRuntimeClass
		nodepool.Config.Labels[NodepoolRuntimeKey] = string(RuntimeTypeGVisorTPU)
		nodepool.Config.Labels[NodepoolTPUTopologyKey] = accelShape
		nodepool.Config.Taints = append(nodepool.Config.Taints, &cspb.NodeTaint{
			Key:    gvisorNodepoolKey,
			Value:  gvisorRuntimeClass,
			Effect: cspb.NodeTaint_NO_SCHEDULE,
		})
	case RuntimeTypeUnsandboxedNvidia:
		accelCount, err := strconv.Atoi(accelShape)
		if err != nil {
			panic(fmt.Sprintf("GPU count must be a valid number, got %v", accelShape))
		}
		if accelCount == 0 {
			panic("GPU count needs to be >=1")
		}
		nodepool.Config.MachineType = DefaultNvidiaMachineType
		nodepool.Config.Accelerators = []*cspb.AcceleratorConfig{
			{
				AcceleratorType:  string(accelType),
				AcceleratorCount: int64(accelCount),
			},
		}
		nodepool.Config.Labels[NodepoolRuntimeKey] = string(RuntimeTypeUnsandboxedNvidia)
		nodepool.Config.Labels[NodepoolNumAcceleratorsKey] = strconv.Itoa(accelCount)
	case RuntimeTypeUnsandboxedTPU:
		nodepool.Config.MachineType = TPUAcceleratorMachineTypeMap[accelType]
		nodepool.PlacementPolicy = &cspb.NodePool_PlacementPolicy{
			TpuTopology: accelShape,
			Type:        cspb.NodePool_PlacementPolicy_COMPACT,
		}
		nodepool.Config.Labels[NodepoolRuntimeKey] = string(RuntimeTypeUnsandboxedTPU)
		nodepool.Config.Labels[NodepoolTPUTopologyKey] = accelShape
	default:
		panic(fmt.Sprintf("unsupported runtime %q", t))
	}
	if accelRes != "" {
		nodepool.Config.ReservationAffinity = &cspb.ReservationAffinity{
			ConsumeReservationType: cspb.ReservationAffinity_SPECIFIC_RESERVATION,
			Key:                    "compute.googleapis.com/reservation-name",
			Values:                 []string{accelRes},
		}
	}
}

// ApplyPodSpec modifies a PodSpec to use this runtime.
func (t RuntimeType) ApplyPodSpec(podSpec *v13.PodSpec) {
	switch t {
	case RuntimeTypeGVisor:
		podSpec.RuntimeClassName = proto.String(gvisorRuntimeClass)
		podSpec.NodeSelector[NodepoolRuntimeKey] = string(RuntimeTypeGVisor)
	case RuntimeTypeUnsandboxed:
		// Allow the pod to schedule on gVisor nodes as well.
		// This enables the use of `--test-nodepool-runtime=runc` to run
		// unsandboxed benchmarks on gVisor test clusters.
		podSpec.Tolerations = append(podSpec.Tolerations, v13.Toleration{
			Effect:   v13.TaintEffectNoSchedule,
			Key:      gvisorNodepoolKey,
			Operator: v13.TolerationOpEqual,
			Value:    gvisorRuntimeClass,
		})
	case RuntimeTypeGVisorNvidia:
		podSpec.RuntimeClassName = proto.String(gvisorRuntimeClass)
		podSpec.NodeSelector[NodepoolRuntimeKey] = string(RuntimeTypeGVisorNvidia)
		podSpec.Tolerations = append(podSpec.Tolerations, v13.Toleration{
			Key:      "nvidia.com/gpu",
			Operator: v13.TolerationOpExists,
		})
	case RuntimeTypeGVisorTPU:
		podSpec.RuntimeClassName = proto.String(gvisorRuntimeClass)
		podSpec.NodeSelector[NodepoolRuntimeKey] = string(RuntimeTypeGVisorTPU)
		podSpec.Tolerations = append(podSpec.Tolerations, v13.Toleration{
			Key:      "google.com/tpu",
			Operator: v13.TolerationOpExists,
		})
	case RuntimeTypeUnsandboxedNvidia:
		podSpec.Tolerations = append(podSpec.Tolerations, v13.Toleration{
			Key:      "nvidia.com/gpu",
			Operator: v13.TolerationOpExists,
		})
		// Allow the pod to schedule on gVisor nodes as well.
		// This enables the use of `--test-nodepool-runtime=runc-nvidia` to run
		// unsandboxed benchmarks on gVisor test clusters.
		podSpec.Tolerations = append(podSpec.Tolerations, v13.Toleration{
			Effect:   v13.TaintEffectNoSchedule,
			Key:      gvisorNodepoolKey,
			Operator: v13.TolerationOpEqual,
			Value:    gvisorRuntimeClass,
		})
	case RuntimeTypeUnsandboxedTPU:
		podSpec.Tolerations = append(podSpec.Tolerations, v13.Toleration{
			Key:      "google.com/tpu",
			Operator: v13.TolerationOpExists,
		})
		podSpec.Tolerations = append(podSpec.Tolerations, v13.Toleration{
			Effect:   v13.TaintEffectNoSchedule,
			Key:      gvisorNodepoolKey,
			Operator: v13.TolerationOpEqual,
			Value:    gvisorRuntimeClass,
		})
	default:
		panic(fmt.Sprintf("unsupported runtime %q", t))
	}
}
