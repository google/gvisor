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
	"errors"
	"fmt"
	"reflect"
	"time"

	cspb "google.golang.org/genproto/googleapis/container/v1"
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

// String returns a string representation of the `ContainerResourcesRequest`.
func (crr ContainerResourcesRequest) String() string {
	return fmt.Sprintf("cpu=%q memory=%q gpu=%v", crr.CPUResources, crr.MemoryResources, crr.GPU)
}

// SetContainerResources sets container resources.
// Sets both the resource limits and requests as container runtimes honor
// them differently.
// `containerName` is optional if the pod has exactly one container.
func SetContainerResources(pod *v13.Pod, containerName string, requests ContainerResourcesRequest) (*v13.Pod, error) {
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

	var containerToChange *v13.Container
	if containerName == "" {
		switch len(pod.Spec.Containers) {
		case 0:
			return nil, fmt.Errorf("no containers found in pod")
		case 1:
			containerToChange = &pod.Spec.Containers[0]
		default:
			return nil, fmt.Errorf("multiple containers found in pod %v, please specify a container name", pod)
		}
	} else {
		for i := range pod.Spec.Containers {
			if pod.Spec.Containers[i].Name == containerName {
				containerToChange = &pod.Spec.Containers[i]
			}
		}
	}
	if containerToChange == nil {
		return nil, fmt.Errorf("container %q not found", containerName)
	}
	containerToChange.Resources = requirements
	return pod, nil
}

// ProbeResources verifies that a pod requesting the given resources can be
// scheduled.
func (n *Namespace) ProbeResources(ctx context.Context, requests ContainerResourcesRequest) error {
	// Configure the pod.
	probe := n.NewAlpinePod("resource-probe", "alpine", []string{"/bin/true"})
	probe, err := n.testCluster.ConfigurePodForRuntimeTestNodepool(ctx, probe)
	if err != nil {
		return fmt.Errorf("failed to configure pod for runtime test nodepool: %w", err)
	}
	if probe, err = SetContainerResources(probe, "", requests); err != nil {
		return fmt.Errorf("failed to set container resources: %w", err)
	}
	resources := probe.Spec.Containers[0].Resources

	// If a pod already exists (e.g. from a past probe), best-effort attempt to delete it:
	deleteCtx, deleteCancel := context.WithTimeout(ctx, 20*time.Second)
	_ = n.testCluster.DeletePod(deleteCtx, probe)
	deleteCancel()

	// Create the pod.
	if _, err := n.testCluster.CreatePod(ctx, probe); err != nil {
		return fmt.Errorf("failed to create probe pod with resources %v: %w", resources, err)
	}

	// Wait up to (ctx - 30 seconds) for the pod to run.
	waitCtx := ctx
	if ctxDeadline, hasDeadline := waitCtx.Deadline(); hasDeadline {
		var waitCancel context.CancelFunc
		waitCtx, waitCancel = context.WithDeadline(ctx, ctxDeadline.Add(-30*time.Second))
		defer waitCancel()
	}
	if err := n.testCluster.WaitForPodRunning(waitCtx, probe); err != nil {
		// Best-effort time-limited deletion.
		deleteCtx, deleteCancel := context.WithTimeout(ctx, 30*time.Second)
		_ = n.testCluster.DeletePod(deleteCtx, probe)
		deleteCancel()

		return fmt.Errorf("probe pod with resources %v did not run: %w", resources, err)
	}

	// Delete the pod.
	if err := n.testCluster.DeletePod(ctx, probe); err != nil {
		return fmt.Errorf("failed to delete probe pod: %w", err)
	}
	return nil
}

// WaitForResources checks that a pod requesting the given resources can be
// scheduled. If they cannot, it will loop until the given context expire or
// the resources become available.
func (n *Namespace) WaitForResources(ctx context.Context, requests ContainerResourcesRequest) error {
	var lastErr error
	for {
		probeCtx, probeCancel := context.WithTimeout(ctx, 90*time.Second)
		err := n.ProbeResources(probeCtx, requests)
		probeCtxErr := probeCtx.Err()
		probeCancel()
		if err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return fmt.Errorf("context expired while waiting for resources %v to be available; last error: %w", requests, lastErr)
			}
			return fmt.Errorf("context expired before ever checking that resources %v are available: %w", requests, err)
		case <-time.After(pollInterval):
			if lastErr == nil || !errors.Is(probeCtxErr, context.DeadlineExceeded) {
				lastErr = err
			}
		}
	}
}

// RuntimeType is a supported runtime for the test nodepool.
type RuntimeType string

// List of known runtime types.
const (
	RuntimeTypeGVisor         = RuntimeType("gvisor")
	RuntimeTypeUnsandboxed    = RuntimeType("runc")
	RuntimeTypeGVisorTPU      = RuntimeType("gvisor-tpu")
	RuntimeTypeUnsandboxedTPU = RuntimeType("runc-tpu")
)

// ApplyNodepool modifies the nodepool to configure it to use the runtime.
func (t RuntimeType) ApplyNodepool(nodepool *cspb.NodePool) {
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
	case RuntimeTypeGVisorTPU:
		nodepool.Config.Labels[gvisorNodepoolKey] = gvisorRuntimeClass
		nodepool.Config.Labels[NodepoolRuntimeKey] = string(RuntimeTypeGVisorTPU)
		nodepool.Config.Taints = append(nodepool.Config.Taints, &cspb.NodeTaint{
			Key:    gvisorNodepoolKey,
			Value:  gvisorRuntimeClass,
			Effect: cspb.NodeTaint_NO_SCHEDULE,
		})
	case RuntimeTypeUnsandboxedTPU:
		nodepool.Config.Labels[NodepoolRuntimeKey] = string(RuntimeTypeUnsandboxedTPU)
	default:
		panic(fmt.Sprintf("unsupported runtime %q", t))
	}
}

// SetNodePlacementPolicyCompact sets the node placement policy to COMPACT
// and with the given TPU topology.
// This is done by reflection because the NodePool_PlacementPolicy proto
// message isn't available in the latest exported version of the genproto API.
// This is only used for TPU nodepools so not critical for most benchmarks.
func SetNodePlacementPolicyCompact(nodepool *cspb.NodePool, tpuTopology string) error {
	placementPolicyField := reflect.ValueOf(nodepool).Elem().FieldByName("PlacementPolicy")
	if !placementPolicyField.IsValid() {
		return errors.New("nodepool does not have a PlacementPolicy field")
	}
	nodePlacementPolicy := reflect.New(placementPolicyField.Type().Elem()).Elem()
	tpuTopologyField := nodePlacementPolicy.FieldByName("TpuTopology")
	if !tpuTopologyField.IsValid() {
		return errors.New("nodepool.PlacementPolicy does not have a TpuTopology field")
	}
	tpuTopologyField.SetString(tpuTopology)
	typeField := nodePlacementPolicy.FieldByName("Type")
	if !typeField.IsValid() {
		return errors.New("nodepool.PlacementPolicy does not have a Type field")
	}
	typeField.SetInt(1 /* cspb.NodePool_PlacementPolicy_COMPACT */)
	// Done.
	placementPolicyField.Set(nodePlacementPolicy.Addr())
	return nil
}

// ApplyPodSpec modifies a PodSpec to use this runtime.
func (t RuntimeType) ApplyPodSpec(podSpec *v13.PodSpec) {
	switch t {
	case RuntimeTypeGVisor:
		podSpec.RuntimeClassName = proto.String(gvisorRuntimeClass)
		podSpec.NodeSelector[NodepoolRuntimeKey] = string(RuntimeTypeGVisor)
		podSpec.Tolerations = append(podSpec.Tolerations, v13.Toleration{
			Key:      "nvidia.com/gpu",
			Operator: v13.TolerationOpExists,
		})
	case RuntimeTypeUnsandboxed:
		podSpec.Tolerations = append(podSpec.Tolerations, v13.Toleration{
			Key:      "nvidia.com/gpu",
			Operator: v13.TolerationOpExists,
		})
		// Allow the pod to schedule on gVisor nodes as well.
		// This enables the use of `--test-nodepool-runtime=runc` to run
		// unsandboxed benchmarks on gVisor test clusters.
		podSpec.Tolerations = append(podSpec.Tolerations, v13.Toleration{
			Effect:   v13.TaintEffectNoSchedule,
			Key:      gvisorNodepoolKey,
			Operator: v13.TolerationOpEqual,
			Value:    gvisorRuntimeClass,
		})
	case RuntimeTypeGVisorTPU:
		podSpec.RuntimeClassName = proto.String(gvisorRuntimeClass)
		podSpec.NodeSelector[NodepoolRuntimeKey] = string(RuntimeTypeGVisorTPU)
		podSpec.Tolerations = append(podSpec.Tolerations, v13.Toleration{
			Key:      "google.com/tpu",
			Operator: v13.TolerationOpExists,
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
