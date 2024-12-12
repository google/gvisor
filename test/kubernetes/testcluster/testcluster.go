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

// Package testcluster wraps the Kubernetes library for common test operations.
// It also provides a TestCluster abstraction for interacting with clusters.
package testcluster

import (
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sync/errgroup"
	cspb "google.golang.org/genproto/googleapis/container/v1"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sync"
	testpb "gvisor.dev/gvisor/test/kubernetes/test_range_config_go_proto"
	appsv1 "k8s.io/api/apps/v1"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// archKey is given to nodepools to mark their architecture. Used here to mark ARM nodepools.
	archKey = "kubernetes.io/arch"

	// k8sApp is used as a label to distinguish between applications.
	k8sApp = "k8s-app"

	// pollInterval is the interval at which we poll for status when waiting for
	// Kubernetes objects.
	pollInterval = 250 * time.Millisecond
)

// Common namespace names.
const (
	// NamespaceDefault is the default namespace for Kubernetes.
	NamespaceDefault = v13.NamespaceDefault

	// NamespaceSanity is used for objects that are part of sanity checks.
	NamespaceSanity = "sanity"

	// NamespaceBenchmark is used for objects that are part of benchmarks.
	NamespaceBenchmark = "benchmark"
)

// NodePoolType is the type of a NodePool.
type NodePoolType string

// Nodepool names.
const (
	// TestRuntimeNodepoolName is the value that marks a "test-runtime-nodepool", or a nodepool where
	// w/ the runtime under test.
	TestRuntimeNodepoolName NodePoolType = "test-runtime-nodepool"
	// ClientNodepoolName is the value that marks a client nodepool. Usually this is a plain GKE
	// nodepool
	ClientNodepoolName NodePoolType = "client-nodepool"
	// TertiaryNodepoolName is the value that marks the tertiary nodepool.
	// This could either be a plain GKE nodepool or could be gVisor-enabled,
	// as configured during test range creation.
	TertiaryNodepoolName NodePoolType = "tertiary-nodepool"
)

// Nodepool keys.
const (
	// NodePoolTypeKey is the key to mark a nodepool as a "test-runtime-nodepool" or a "client-nodepool"
	NodePoolTypeKey = "nodepool-type"
	// NodepoolRuntimeKey is the key to mark the runtime used by a nodepool.
	NodepoolRuntimeKey = "runtime"
	// NodepoolNumAcceleratorsKey is the key to mark the number of accelerators in a nodepool.
	NodepoolNumAcceleratorsKey = "num-accelerators"
	// NodepoolTPUTopologyKey is the key to mark the TPU topology used by a nodepool.
	NodepoolTPUTopologyKey = "tpu-topology"
	// NodepoolInstanceTypeKey is the key to mark the instance type used by a nodepool.
	NodepoolInstanceTypeKey = "node.kubernetes.io/instance-type"
	// Name of the TPU accelerator key used in Pod.Spec.NodeSelector.
	NodepoolTPUAcceleratorSelectorKey = "cloud.google.com/gke-tpu-accelerator"
	// Name of the TPU topology key used in Pod.Spec.NodeSelector.
	NodepoolTPUTopologySelectorKey = "cloud.google.com/gke-tpu-topology"
)

// Default machine types.
var (
	// DefaultMachineType is the default machine type to use for specs and create-default.
	DefaultMachineType = "n2-standard-4"
	// DefaultNvidiaMachineType is the default machine type for nvidia.
	DefaultNvidiaMachineType = "n1-standard-4"
	// TPUAcceleratorMachineTypeMap maps TPU types to the machine type to use.
	TPUAcceleratorMachineTypeMap = map[AcceleratorType]string{
		AcceleratorTypeV4PodTPU: "ct4p-hightpu-4t",
	}
)

// GKE Sandbox gVisor runtime.
const (
	// gvisorNodepoolKey the key for the label given to GKE Sandbox nodepools.
	gvisorNodepoolKey = "sandbox.gke.io/runtime"
	// gvisorRuntimeClass the runtimeClassName used for GKE Sandbox pods.
	gvisorRuntimeClass = "gvisor"
)

// CPUArchitecture is the CPU architecture of a node.
// It is stored under the archKey label in node labels.
type CPUArchitecture string

const (
	// CPUArchitectureX86 is the x86 CPU architecture.
	CPUArchitectureX86 = CPUArchitecture("amd64")
	// CPUArchitectureARM is the ARM CPU architecture.
	CPUArchitectureARM = CPUArchitecture("arm64")
)

// AcceleratorType is the gpu type to be used.
type AcceleratorType string

// List of supported GPUs.
const (
	AcceleratorTypeTeslaT4GPU = AcceleratorType("nvidia-tesla-t4")
	AcceleratorTypeA100GPU    = AcceleratorType("nvidia-tesla-a100")
	AcceleratorTypeL4GPU      = AcceleratorType("nvidia-tesla-l4")
	AcceleratorTypeV4PodTPU   = AcceleratorType("tpu-v4-pod")
)

// TestCluster wraps clusters with their individual ClientSets so that helper methods can be called.
type TestCluster struct {
	clusterName string

	client KubernetesClient

	// testNodepoolRuntimeOverride, if set, overrides the runtime used for pods
	// running on the test nodepool. If unset, the test nodepool's default
	// runtime is used.
	testNodepoolRuntimeOverride RuntimeType

	// nodepoolsMu controls the initialization of `nodepools`.
	nodepoolsMu sync.Mutex

	// nodepools is a map of NodePools that exist in this cluster.
	// It is nil by default and initialized lazily.
	nodepools map[NodePoolType]*NodePool
}

// NodePool is a set of nodes in a TestCluster.
// These nodes share a set of relevant labels and are used to segment the
// set of nodes in a Kubernetes cluster.
// In the context of Kubernetes tests and benchmarks, these pools are used
// to separate where workloads of each type schedule and run.
// NodePools are expected to be uniform (i.e. same amount of resources and
// reasonably similar hardware) so that simple pod scheduling can determine
// where to consume resources.
type NodePool struct {
	// nodePoolType is the type of the nodepool.
	// It is used to identify the nodes in the cluster, and therefore as a
	// scheduling constraint for pods to run exclusively on these nodes.
	nodePooltype NodePoolType

	// runtime is the container runtime to use when scheduling pods on this
	// nodepool by default.
	runtime RuntimeType

	// cpuArchitecture is the CPU architecture of nodes in the nodepool.
	cpuArchitecture CPUArchitecture

	// acceleratorType is the accelerator type present on nodes in the nodepool.
	// Empty string if the nodes have no accelerators.
	acceleratorType AcceleratorType

	// numAccelerators is the number of accelerators present on nodes in the
	// nodepool.
	numAccelerators int

	// tpuTopology is the TPU topology used by the nodepool.
	// Empty string if the nodepool has no TPU-based accelerators.
	tpuTopology string
}

// NewTestClusterFromProto returns a new TestCluster client from a proto.
func NewTestClusterFromProto(ctx context.Context, cluster *testpb.Cluster) (*TestCluster, error) {
	config, err := clientcmd.BuildConfigFromFlags("" /*masterURL*/, cluster.GetCredentialFile())
	if err != nil {
		return nil, fmt.Errorf("BuildConfigFromFlags: %w", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("kubernetes.NewForConfig: %w", err)
	}
	var clusterPB cspb.Cluster
	if err := cluster.GetCluster().UnmarshalTo(&clusterPB); err != nil {
		return nil, fmt.Errorf("cannot unmarshal cluster: %w", err)
	}
	clusterName := clusterPB.GetName()
	return NewTestClusterFromClient(clusterName, client), nil
}

// NewTestClusterFromClient returns a new TestCluster client with a given client.
func NewTestClusterFromClient(clusterName string, client kubernetes.Interface) *TestCluster {
	return NewTestClusterFromKubernetesClient(clusterName, &simpleClient{client})
}

// NewTestClusterFromKubernetesClient returns a new TestCluster client with a
// given KubernetesClient.
func NewTestClusterFromKubernetesClient(clusterName string, client KubernetesClient) *TestCluster {
	return &TestCluster{
		clusterName:                 clusterName,
		client:                      client,
		testNodepoolRuntimeOverride: "",
	}
}

// GetName returns this cluster's name.
func (t *TestCluster) GetName() string {
	return t.clusterName
}

// GetGVisorRuntimeLabelMap returns the gVisor runtime key-value pair used
// on gVisor-runtime-enabled nodes.
func (t *TestCluster) GetGVisorRuntimeLabelMap() map[string]string {
	return map[string]string{
		gvisorNodepoolKey: gvisorRuntimeClass,
	}
}

// GetGVisorRuntimeToleration returns a pod scheduling toleration that
// allows the pod to schedule on gVisor-runtime-enabled nodes.
func (t *TestCluster) GetGVisorRuntimeToleration() v13.Toleration {
	return v13.Toleration{
		Key:      gvisorNodepoolKey,
		Operator: v13.TolerationOpEqual,
		Value:    gvisorRuntimeClass,
		Effect:   v13.TaintEffectNoSchedule,
	}
}

// OverrideTestNodepoolRuntime overrides the runtime used for pods running on
// the test nodepool. If unset, the test nodepool's default runtime is used.
func (t *TestCluster) OverrideTestNodepoolRuntime(testRuntime RuntimeType) {
	t.testNodepoolRuntimeOverride = testRuntime
}

// createNamespace creates a namespace.
func (t *TestCluster) createNamespace(ctx context.Context, namespace *v13.Namespace) (*v13.Namespace, error) {
	return request(ctx, t.client, func(ctx context.Context, client kubernetes.Interface) (*v13.Namespace, error) {
		return client.CoreV1().Namespaces().Create(ctx, namespace, v1.CreateOptions{})
	})
}

// getNamespace returns the given namespace in the cluster if it exists.
func (t *TestCluster) getNamespace(ctx context.Context, namespaceName string) (*v13.Namespace, error) {
	return request(ctx, t.client, func(ctx context.Context, client kubernetes.Interface) (*v13.Namespace, error) {
		return client.CoreV1().Namespaces().Get(ctx, namespaceName, v1.GetOptions{})
	})
}

// deleteNamespace is a helper method to delete a namespace.
func (t *TestCluster) deleteNamespace(ctx context.Context, namespaceName string) error {
	err := t.client.Do(ctx, func(ctx context.Context, client kubernetes.Interface) error {
		return client.CoreV1().Namespaces().Delete(ctx, namespaceName, v1.DeleteOptions{})
	})
	if err != nil {
		return err
	}
	// Wait for the namespace to disappear or for the context to expire.
	for ctx.Err() == nil {
		if _, err := t.getNamespace(ctx, namespaceName); err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return ctx.Err()
}

// getNodePool returns the NodePool of the given type.
// If nodepools have not been initialized yet, this method will initialize
// them.
func (t *TestCluster) getNodePool(ctx context.Context, nodepoolType NodePoolType) (*NodePool, error) {
	t.nodepoolsMu.Lock()
	defer t.nodepoolsMu.Unlock()
	if t.nodepools == nil {
		nodes, err := request(ctx, t.client, func(ctx context.Context, client kubernetes.Interface) (*v13.NodeList, error) {
			return client.CoreV1().Nodes().List(ctx, v1.ListOptions{})
		})
		if err != nil {
			return nil, fmt.Errorf("cannot list nodes: %w", err)
		}
		nodepools := make(map[NodePoolType]*NodePool, len(nodes.Items))
		for _, node := range nodes.Items {
			npType := NodePoolType(node.Labels[NodePoolTypeKey])
			if npType == "" {
				continue
			}
			npRuntime := RuntimeType(node.Labels[NodepoolRuntimeKey])
			if npRuntime == "" {
				continue
			}
			npArchitecture := CPUArchitecture(node.Labels[archKey])
			if npArchitecture == "" {
				continue
			}
			npAcceleratorType := AcceleratorType(node.Labels[NodepoolTPUAcceleratorSelectorKey])
			if npAcceleratorType == "" {
				// Attempt to derive it from instance type if possible.
				if instanceType, hasInstanceType := node.Labels[NodepoolInstanceTypeKey]; hasInstanceType {
					for accelType, machineType := range TPUAcceleratorMachineTypeMap {
						if machineType == instanceType {
							npAcceleratorType = accelType
							break
						}
					}
				}
			}
			npNumAccelerators := 0
			if countStr, hasCount := node.Labels[NodepoolNumAcceleratorsKey]; hasCount {
				if npNumAccelerators, err = strconv.Atoi(countStr); err != nil {
					return nil, fmt.Errorf("cannot parse accelerator count (%q) value %q as an integer: %w", NodepoolNumAcceleratorsKey, countStr, err)
				}
			}
			npTPUTopology := node.Labels[NodepoolTPUTopologyKey]
			existingNodepool, ok := nodepools[npType]
			if !ok {
				nodepools[npType] = &NodePool{
					nodePooltype:    npType,
					runtime:         npRuntime,
					cpuArchitecture: npArchitecture,
					acceleratorType: npAcceleratorType,
					numAccelerators: npNumAccelerators,
					tpuTopology:     npTPUTopology,
				}
				continue
			}
			if existingNodepool.runtime != npRuntime {
				return nil, fmt.Errorf("nodes in nodepool %q have conflicting runtimes: %v vs %v", npType, existingNodepool.runtime, npRuntime)
			}
			if existingNodepool.cpuArchitecture != npArchitecture {
				return nil, fmt.Errorf("nodes in nodepool %q have conflicting architectures: %v vs %v", npType, existingNodepool.cpuArchitecture, npArchitecture)
			}
			if existingNodepool.acceleratorType != npAcceleratorType {
				return nil, fmt.Errorf("nodes in nodepool %q have conflicting accelerator types: %v vs %v", npType, existingNodepool.acceleratorType, npAcceleratorType)
			}
			if existingNodepool.numAccelerators != npNumAccelerators {
				return nil, fmt.Errorf("nodes in nodepool %q have conflicting accelerator counts: %v vs %v", npType, existingNodepool.numAccelerators, npNumAccelerators)
			}
			if existingNodepool.tpuTopology != npTPUTopology {
				return nil, fmt.Errorf("nodes in nodepool %q have conflicting TPU topologies: %v vs %v", npType, existingNodepool.tpuTopology, npTPUTopology)
			}
		}
		t.nodepools = nodepools
	}
	np, ok := t.nodepools[nodepoolType]
	if !ok {
		return nil, fmt.Errorf("cluster %q contains no %q nodepool", t.GetName(), nodepoolType)
	}
	return np, nil
}

// HasGVisorTestRuntime returns whether the test nodes in this cluster
// use the gVisor runtime.
func (t *TestCluster) HasGVisorTestRuntime(ctx context.Context) (bool, error) {
	testNodePool, err := t.getNodePool(ctx, TestRuntimeNodepoolName)
	if err != nil {
		return false, err
	}
	return testNodePool.runtime == RuntimeTypeGVisor || testNodePool.runtime == RuntimeTypeGVisorTPU, nil
}

// CreatePod is a helper to create a pod.
func (t *TestCluster) CreatePod(ctx context.Context, pod *v13.Pod) (*v13.Pod, error) {
	if pod.GetObjectMeta().GetNamespace() == "" {
		pod.SetNamespace(NamespaceDefault)
	}
	return request(ctx, t.client, func(ctx context.Context, client kubernetes.Interface) (*v13.Pod, error) {
		return client.CoreV1().Pods(pod.GetNamespace()).Create(ctx, pod, v1.CreateOptions{})
	})
}

// GetPod is a helper method to Get a pod's metadata.
func (t *TestCluster) GetPod(ctx context.Context, pod *v13.Pod) (*v13.Pod, error) {
	return request(ctx, t.client, func(ctx context.Context, client kubernetes.Interface) (*v13.Pod, error) {
		return client.CoreV1().Pods(pod.GetNamespace()).Get(ctx, pod.GetName(), v1.GetOptions{})
	})
}

// ListPods is a helper method to List pods in a cluster.
func (t *TestCluster) ListPods(ctx context.Context, namespace string) (*v13.PodList, error) {
	return request(ctx, t.client, func(ctx context.Context, client kubernetes.Interface) (*v13.PodList, error) {
		return client.CoreV1().Pods(namespace).List(ctx, v1.ListOptions{})
	})
}

// DeletePod is a helper method to delete a pod.
func (t *TestCluster) DeletePod(ctx context.Context, pod *v13.Pod) error {
	err := t.client.Do(ctx, func(ctx context.Context, client kubernetes.Interface) error {
		return client.CoreV1().Pods(pod.GetNamespace()).Delete(ctx, pod.GetName(), v1.DeleteOptions{})
	})
	if err != nil {
		return err
	}
	// Wait for the pod to disappear or for the context to expire.
	for ctx.Err() == nil {
		if _, err := t.GetPod(ctx, pod); err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return ctx.Err()
}

// GetLogReader gets an io.ReadCloser from which logs can be read. It is the caller's
// responsibility to close it.
func (t *TestCluster) GetLogReader(ctx context.Context, pod *v13.Pod, opts v13.PodLogOptions) (io.ReadCloser, error) {
	return request(ctx, t.client, func(ctx context.Context, client kubernetes.Interface) (io.ReadCloser, error) {
		return client.CoreV1().Pods(pod.GetNamespace()).GetLogs(pod.GetName(), &opts).Stream(ctx)
	})
}

// ReadPodLogs reads logs from a pod.
func (t *TestCluster) ReadPodLogs(ctx context.Context, pod *v13.Pod) (string, error) {
	rdr, err := t.GetLogReader(ctx, pod, v13.PodLogOptions{})
	if err != nil {
		return "", fmt.Errorf("GetLogReader on cluster %q pod %q: %v", t.GetName(), pod.GetName(), err)
	}
	out, err := io.ReadAll(rdr)
	if err != nil {
		return "", fmt.Errorf("failed to read from pod %q: %v", pod.GetName(), err)
	}
	return string(out), nil
}

// WaitForPodRunning is a helper method to wait for a pod to be running.
func (t *TestCluster) WaitForPodRunning(ctx context.Context, pod *v13.Pod) error {
	_, err := t.doWaitForPod(ctx, pod, func(p v13.PodPhase) bool { return p == v13.PodRunning })
	return err
}

// WaitForPodCompleted is a helper method to wait for a pod to be completed.
func (t *TestCluster) WaitForPodCompleted(ctx context.Context, pod *v13.Pod) error {
	_, err := t.doWaitForPod(ctx, pod, func(p v13.PodPhase) bool { return p == v13.PodSucceeded })
	return err
}

// WaitForPodTerminated is a helper method to wait for a pod to exit,
// whether it succeeded or failed.
func (t *TestCluster) WaitForPodTerminated(ctx context.Context, pod *v13.Pod) (v13.PodPhase, error) {
	return t.doWaitForPod(ctx, pod, func(p v13.PodPhase) bool { return p == v13.PodRunning || p == v13.PodFailed })
}

// doWaitForPod waits for a pod to complete based on a given v13.PodPhase.
func (t *TestCluster) doWaitForPod(ctx context.Context, pod *v13.Pod, phasePredicate func(v13.PodPhase) bool) (v13.PodPhase, error) {
	podLogger := log.BasicRateLimitedLogger(5 * time.Minute)
	startTime := time.Now()
	startLogTime := startTime.Add(3 * time.Minute)

	var p *v13.Pod
	var err error
	pollCh := time.NewTicker(pollInterval)
	defer pollCh.Stop()
	for {
		select {
		case <-pollCh.C:
			if p, err = t.GetPod(ctx, pod); err != nil {
				return v13.PodUnknown, fmt.Errorf("failed to poll pod: %w", err)
			}
		case <-ctx.Done():
			return v13.PodUnknown, fmt.Errorf("context expired waiting for pod %q: %w", pod.GetName(), ctx.Err())
		}
		if p.Status.Reason == v13.PodReasonUnschedulable {
			return v13.PodPending, fmt.Errorf("pod %q cannot be scheduled: reason: %q message: %q", p.GetName(), p.Status.Reason, p.Status.Message)
		}

		for _, c := range p.Status.Conditions {
			if strings.Contains(c.Reason, v13.PodReasonUnschedulable) {
				return v13.PodPending, fmt.Errorf("pod %q cannot be scheduled: reason: %q message: %q", p.GetName(), c.Reason, c.Message)
			}
		}

		if phasePredicate(p.Status.Phase) {
			return p.Status.Phase, nil
		}
		if p.Status.Phase == v13.PodFailed {
			return v13.PodFailed, fmt.Errorf("pod %q failed: %s", p.GetName(), p.Status.Message)
		}
		if time.Now().After(startLogTime) {
			podLogger.Infof("Still waiting for pod %q after %v; pod status: %v", p.GetName(), time.Since(startTime), p.Status)
		}
	}
}

// RuntimeTestNodepoolArchitecture returns the CPU architecture of the test nodepool.
func (t *TestCluster) RuntimeTestNodepoolArchitecture(ctx context.Context) (CPUArchitecture, error) {
	np, err := t.getNodePool(ctx, TestRuntimeNodepoolName)
	if err != nil {
		return "", err
	}
	return np.cpuArchitecture, nil
}

// configureDaemonSetForNodepool configures the DaemonSet to run on a given nodepool.
func (t *TestCluster) configureDaemonSetForNodepool(ctx context.Context, ds *appsv1.DaemonSet, nodepoolType NodePoolType) error {
	np, err := t.getNodePool(ctx, nodepoolType)
	if err != nil {
		return err
	}
	if ds.Labels == nil {
		ds.Labels = make(map[string]string)
	}
	return t.applyCommonPodConfigurations(ctx, np, &ds.Spec.Template.Spec)
}

// configurePodForNodepool configures the pod to run on a given nodepool.
func (t *TestCluster) configurePodForNodepool(ctx context.Context, pod *v13.Pod, nodepoolType NodePoolType) (*v13.Pod, error) {
	np, err := t.getNodePool(ctx, nodepoolType)
	if err != nil {
		return nil, err
	}
	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	if err := t.applyCommonPodConfigurations(ctx, np, &pod.Spec); err != nil {
		return nil, err
	}
	return pod, nil
}

// ConfigureDaemonSetForRuntimeTestNodepool configures the DaemonSet to run
// on the test runtime.
func (t *TestCluster) ConfigureDaemonSetForRuntimeTestNodepool(ctx context.Context, ds *appsv1.DaemonSet) error {
	return t.configureDaemonSetForNodepool(ctx, ds, TestRuntimeNodepoolName)
}

// ConfigurePodForRuntimeTestNodepool configures the pod to run on the test runtime.
func (t *TestCluster) ConfigurePodForRuntimeTestNodepool(ctx context.Context, pod *v13.Pod) (*v13.Pod, error) {
	return t.configurePodForNodepool(ctx, pod, TestRuntimeNodepoolName)
}

// ConfigurePodForClientNodepool configures the pod to run on the client
// nodepool.
func (t *TestCluster) ConfigurePodForClientNodepool(ctx context.Context, pod *v13.Pod) (*v13.Pod, error) {
	return t.configurePodForNodepool(ctx, pod, ClientNodepoolName)
}

// ConfigurePodForTertiaryNodepool configures the pod to run on the tertiary
// nodepool.
func (t *TestCluster) ConfigurePodForTertiaryNodepool(ctx context.Context, pod *v13.Pod) (*v13.Pod, error) {
	return t.configurePodForNodepool(ctx, pod, TertiaryNodepoolName)
}

func (t *TestCluster) applyCommonPodConfigurations(ctx context.Context, np *NodePool, podSpec *v13.PodSpec) error {
	if podSpec.NodeSelector == nil {
		podSpec.NodeSelector = make(map[string]string)
	}
	// Force the pod to run on this nodepool.
	podSpec.NodeSelector[NodePoolTypeKey] = string(np.nodePooltype)

	// Figure out which runtime to use for this pod, either by flag override or
	// autodetection based on the nodepool configuration.
	var applyRuntime = np.runtime
	if np.nodePooltype == TestRuntimeNodepoolName && t.testNodepoolRuntimeOverride != "" {
		applyRuntime = t.testNodepoolRuntimeOverride
	}
	// Apply the runtime we've chosen, whether by override or autodetection.
	applyRuntime.ApplyPodSpec(podSpec)

	// If the nodepool has accelerators, copy the number of them as a node
	// selector option.
	// This doesn't really constrain the pod further, but allows
	// this number to be carried over when setting pod resources.
	if np.numAccelerators > 0 {
		podSpec.NodeSelector[NodepoolNumAcceleratorsKey] = strconv.Itoa(np.numAccelerators)
	}
	if np.acceleratorType != "" {
		podSpec.NodeSelector[NodepoolTPUAcceleratorSelectorKey] = string(np.acceleratorType)
	}
	if np.tpuTopology != "" {
		podSpec.NodeSelector[NodepoolTPUTopologySelectorKey] = np.tpuTopology
	}

	// If the nodepool is an ARM nodepool, apply ARM tolerations.
	if np.cpuArchitecture == CPUArchitectureARM {
		podSpec.NodeSelector[archKey] = string(CPUArchitectureARM)
		podSpec.Tolerations = append(podSpec.Tolerations, v13.Toleration{
			Key:      archKey,
			Value:    string(CPUArchitectureARM),
			Operator: v13.TolerationOpEqual,
			Effect:   v13.TaintEffectNoSchedule,
		})
	}
	return nil
}

// ContainerDurationSecondsByName gets the runtime of a container reported by the kubelet by name.
// The kubelet reports runtime at second granularity.
func (t *TestCluster) ContainerDurationSecondsByName(ctx context.Context, pod *v13.Pod, containerName string) (time.Duration, error) {
	p, err := t.GetPod(ctx, pod)
	if err != nil {
		return 0, fmt.Errorf("GetPod: %w", err)
	}
	for _, c := range p.Status.ContainerStatuses {
		fmt.Println(c.Name)
		if c.Name != containerName {
			continue
		}
		if c.State.Terminated == nil {
			return 0, fmt.Errorf("failed to get runtime seconds: terminated is nil: %+v", c.State)
		}
		start := c.State.Terminated.StartedAt
		end := c.State.Terminated.FinishedAt
		result := end.Unix() - start.Unix()
		if result < 0 {
			return 0, fmt.Errorf("invalid result %d: %+v", result, c.State)
		}
		return time.Duration(result) * time.Second, nil
	}
	return 0, fmt.Errorf("container %q not found: %+v", containerName, pod.Status.ContainerStatuses)
}

// CreateService is a helper method to create a service in a cluster.
func (t *TestCluster) CreateService(ctx context.Context, service *v13.Service) (*v13.Service, error) {
	return request(ctx, t.client, func(ctx context.Context, client kubernetes.Interface) (*v13.Service, error) {
		return client.CoreV1().Services(service.GetNamespace()).Create(ctx, service, v1.CreateOptions{})
	})
}

// GetService is a helper method to get a service in a cluster.
func (t *TestCluster) GetService(ctx context.Context, service *v13.Service) (*v13.Service, error) {
	return request(ctx, t.client, func(ctx context.Context, client kubernetes.Interface) (*v13.Service, error) {
		return client.CoreV1().Services(service.GetNamespace()).Get(ctx, service.GetName(), v1.GetOptions{})
	})
}

// ListServices is a helper method to List services in a cluster.
func (t *TestCluster) ListServices(ctx context.Context, namespace string) (*v13.ServiceList, error) {
	return request(ctx, t.client, func(ctx context.Context, client kubernetes.Interface) (*v13.ServiceList, error) {
		return client.CoreV1().Services(namespace).List(ctx, v1.ListOptions{})
	})
}

// DeleteService is a helper to delete a given service.
func (t *TestCluster) DeleteService(ctx context.Context, service *v13.Service) error {
	err := t.client.Do(ctx, func(ctx context.Context, client kubernetes.Interface) error {
		return client.CoreV1().Services(service.GetNamespace()).Delete(ctx, service.GetName(), v1.DeleteOptions{})
	})
	if err != nil {
		return err
	}
	// Wait for the service to disappear or for the context to expire.
	for ctx.Err() == nil {
		if _, err := t.GetService(ctx, service); err != nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	return ctx.Err()
}

// WaitForServiceReady waits until a service is ready.
func (t *TestCluster) WaitForServiceReady(ctx context.Context, service *v13.Service) error {
	pollCh := time.NewTicker(pollInterval)
	var lastService *v13.Service
	defer pollCh.Stop()
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("context expired waiting for service %q: %w (last: %v)", service.GetName(), ctx.Err(), lastService)
		case <-pollCh.C:
			s, err := t.GetService(ctx, service)
			if err != nil {
				return fmt.Errorf("cannot look up service %q: %w", service.GetName(), err)
			}
			hasIP := s.Spec.ClusterIP != "" || (len(s.Spec.ClusterIPs) > 0 && s.Spec.ClusterIPs[0] != "")
			if hasIP {
				return nil
			}
			lastService = s
		}
	}
}

// GetIPFromService returns the IP on a service.
func GetIPFromService(service *v13.Service) string {
	return service.Spec.ClusterIP
}

// CreatePersistentVolume creates a persistent volume.
func (t *TestCluster) CreatePersistentVolume(ctx context.Context, volume *v13.PersistentVolumeClaim) (*v13.PersistentVolumeClaim, error) {
	if volume.GetObjectMeta().GetNamespace() == "" {
		volume.SetNamespace(NamespaceDefault)
	}
	return request(ctx, t.client, func(ctx context.Context, client kubernetes.Interface) (*v13.PersistentVolumeClaim, error) {
		return client.CoreV1().PersistentVolumeClaims(volume.GetNamespace()).Create(ctx, volume, v1.CreateOptions{})
	})
}

// DeletePersistentVolume deletes a persistent volume.
func (t *TestCluster) DeletePersistentVolume(ctx context.Context, volume *v13.PersistentVolumeClaim) error {
	return t.client.Do(ctx, func(ctx context.Context, client kubernetes.Interface) error {
		return client.CoreV1().PersistentVolumeClaims(volume.GetNamespace()).Delete(ctx, volume.GetName(), v1.DeleteOptions{})
	})
}

// CreateDaemonset creates a daemonset with default options.
func (t *TestCluster) CreateDaemonset(ctx context.Context, ds *appsv1.DaemonSet) (*appsv1.DaemonSet, error) {
	if ds.GetObjectMeta().GetNamespace() == "" {
		ds.SetNamespace(NamespaceDefault)
	}
	return request(ctx, t.client, func(ctx context.Context, client kubernetes.Interface) (*appsv1.DaemonSet, error) {
		return client.AppsV1().DaemonSets(ds.GetNamespace()).Create(ctx, ds, v1.CreateOptions{})
	})
}

// GetDaemonset gets a daemonset.
func (t *TestCluster) GetDaemonset(ctx context.Context, ds *appsv1.DaemonSet) (*appsv1.DaemonSet, error) {
	return request(ctx, t.client, func(ctx context.Context, client kubernetes.Interface) (*appsv1.DaemonSet, error) {
		return client.AppsV1().DaemonSets(ds.GetNamespace()).Get(ctx, ds.GetName(), v1.GetOptions{})
	})
}

// DeleteDaemonset deletes a daemonset from this cluster.
func (t *TestCluster) DeleteDaemonset(ctx context.Context, ds *appsv1.DaemonSet) error {
	return t.client.Do(ctx, func(ctx context.Context, client kubernetes.Interface) error {
		return client.AppsV1().DaemonSets(ds.GetNamespace()).Delete(ctx, ds.GetName(), v1.DeleteOptions{})
	})
}

// GetPodsInDaemonSet returns the list of pods of the given DaemonSet.
func (t *TestCluster) GetPodsInDaemonSet(ctx context.Context, ds *appsv1.DaemonSet) ([]v13.Pod, error) {
	listOptions := v1.ListOptions{}
	if appLabel, found := ds.Spec.Template.Labels[k8sApp]; found {
		listOptions.LabelSelector = fmt.Sprintf("%s=%s", k8sApp, appLabel)
	}
	pods, err := request(ctx, t.client, func(ctx context.Context, client kubernetes.Interface) (*v13.PodList, error) {
		return client.CoreV1().Pods(ds.ObjectMeta.Namespace).List(ctx, listOptions)
	})
	if err != nil {
		return nil, err
	}
	var dsPods []v13.Pod
	for _, pod := range pods.Items {
		if !strings.HasPrefix(pod.Name, ds.ObjectMeta.Name) {
			continue // Not part of the DaemonSet.
		}
		dsPods = append(dsPods, pod)
	}
	return dsPods, nil
}

// WaitForDaemonset waits until a daemonset has propagated containers across the affected nodes.
func (t *TestCluster) WaitForDaemonset(ctx context.Context, ds *appsv1.DaemonSet) error {
	pollCh := time.NewTicker(pollInterval)
	defer pollCh.Stop()
	// Poll-based loop to wait for the DaemonSet to be ready.
	for {
		d, err := t.GetDaemonset(ctx, ds)
		if err != nil {
			return fmt.Errorf("failed to get daemonset %q: %v", ds.GetName(), err)
		}
		if d.Status.NumberReady == d.Status.DesiredNumberScheduled && d.Status.DesiredNumberScheduled > 0 && d.Status.NumberUnavailable == 0 {
			break
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("context expired waiting for daemonset %q: %w; last daemonset status: NumberReady=%d DesiredNumberScheduled=%d NumberUnavailable=%d; full: %v", ds.GetName(), ctx.Err(), d.Status.NumberReady, d.Status.DesiredNumberScheduled, d.Status.NumberUnavailable, d)
		case <-pollCh.C:
		}
	}
	var lastBadPod v13.Pod
	for {
		pods, err := t.GetPodsInDaemonSet(ctx, ds)
		if err != nil {
			return fmt.Errorf("failed to get pods in daemonset: %v", err)
		}
		if len(pods) == 0 {
			return fmt.Errorf("no pods found in daemonset %q", ds.GetName())
		}
		allOK := true
		for _, pod := range pods {
			switch pod.Status.Phase {
			case v13.PodRunning, v13.PodSucceeded:
				// OK, do nothing.
			default:
				lastBadPod = pod
				allOK = false
			}
		}
		if allOK {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("context expired waiting for daemonset %q: %w; last bad pod: %v", ds.GetName(), ctx.Err(), lastBadPod)
		case <-pollCh.C:
		}
	}
}

// StreamDaemonSetLogs streams the contents of a container from the given
// DaemonSet. The callback function is called once per node that the DaemonSet
// schedules on, with the reader corresponding to that node. The callback
// function is expected to close the reader.
// StreamDaemonSetLogs returns once the DaemonSet is ready everywhere that
// it is meant to be scheduled.
func (t *TestCluster) StreamDaemonSetLogs(ctx context.Context, ds *appsv1.DaemonSet, opts v13.PodLogOptions, fn func(context.Context, v13.Pod, io.ReadCloser) error) error {
	errGroup, groupCtx := errgroup.WithContext(ctx)
	nodesSeen := make(map[string]struct{})
	nodesErr := make(map[string]error)

	// refreshPods queries all matching pods in the cluster and starts new
	// log streams for every pod that schedules on a node we haven't seen yet.
	refreshPods := func() error {
		pods, err := t.GetPodsInDaemonSet(ctx, ds)
		if err != nil {
			return err
		}
		for _, pod := range pods {
			pod := pod
			if pod.Spec.NodeName == "" {
				continue // No node assigned yet.
			}
			if _, seen := nodesSeen[pod.Spec.NodeName]; seen {
				continue // Node already seen.
			}
			logReader, err := t.GetLogReader(ctx, &pod, opts)
			if err != nil {
				// This can happen if the container hasn't run yet, for example
				// because other init containers that run earlier are still executing.
				// We retain this error in `nodesErr` but clear it if it later becomes
				// OK for this node.
				nodesErr[pod.Spec.NodeName] = fmt.Errorf("failed to stream logs from pod %q/%q on node %q: %v", pod.GetNamespace(), pod.GetName(), pod.Spec.NodeName, err)
				continue
			}
			nodesSeen[pod.Spec.NodeName] = struct{}{}
			nodesErr[pod.Spec.NodeName] = nil
			errGroup.Go(func() error {
				return fn(groupCtx, pod, logReader)
			})
		}
		return nil
	}

	timeTicker := time.NewTicker(pollInterval)
	defer timeTicker.Stop()

	// Iterate and stop once the DaemonSet is fully Ready.
	var loopError error
	var lastDS *appsv1.DaemonSet
Outer:
	for {
		select {
		case <-ctx.Done():
			if lastDS != nil {
				loopError = fmt.Errorf("context canceled before healthy; last status: %#v", lastDS.Status)
			} else {
				loopError = fmt.Errorf("context canceled before healthy")
			}
			break Outer
		case <-timeTicker.C:
			d, err := t.GetDaemonset(ctx, ds)
			if err != nil {
				loopError = fmt.Errorf("failed to get DaemonSet: %v", err)
				break Outer
			}
			lastDS = d
			if err := refreshPods(); err != nil {
				loopError = err
				break Outer
			}
			if d.Status.NumberReady == d.Status.DesiredNumberScheduled && d.Status.DesiredNumberScheduled > 0 && d.Status.NumberUnavailable == 0 {
				break Outer
			}
		}
	}
	groupErr := errGroup.Wait()
	for _, err := range nodesErr {
		if err != nil {
			return err
		}
	}
	if loopError != nil {
		return loopError
	}
	return groupErr
}
