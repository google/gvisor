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

	cspb "cloud.google.com/go/container/apiv1/containerpb"
	"golang.org/x/sync/errgroup"
	testpb "gvisor.dev/gvisor/test/kubernetes/test_range_config_go_proto"
	appsv1 "k8s.io/api/apps/v1"
	v13 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	// archKey is given to nodepools to mark their architecture. Used here to mark ARM nodepools.
	archKey = "kubernetes.io/arch"
	// armValue marks an ARM nodepool.
	armValue = "arm64"

	// k8sApp is used as a label to distinguish between applications.
	k8sApp = "k8s-app"
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

// Nodepool names.
const (
	// TestRuntimeNodepoolName is the value that marks a "test-runtime-nodepool", or a nodepool where
	// w/ the runtime under test.
	TestRuntimeNodepoolName = "test-runtime-nodepool"
	// ClientNodepoolName is the value that marks a client nodepool. Usually this is a plain GKE
	// nodepool
	ClientNodepoolName = "client-nodepool"
	// TertiaryNodepoolName is the value that marks the tertiary nodepool.
	// This could either be a plain GKE nodepool or could be gVisor-enabled,
	// as configured during test range creation.
	TertiaryNodepoolName = "tertiary-nodepool"
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
	// Name of the nodepool key used in Pod.Spec.NodeSelector.
	NodePoolSelectorKey = "cloud.google.com/gke-nodepool"
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
	cluster *testpb.Cluster
	client  kubernetes.Interface

	// testNodepoolRuntimeOverride, if set, overrides the runtime used for pods
	// running on the test nodepool. If unset, the test nodepool's default
	// runtime is used.
	testNodepoolRuntimeOverride RuntimeType
}

// NewTestCluster returns a new TestCluster client.
func NewTestCluster(cluster *testpb.Cluster) (*TestCluster, error) {
	config, err := clientcmd.BuildConfigFromFlags("" /*masterURL*/, cluster.GetCredentialFile())
	if err != nil {
		return nil, fmt.Errorf("BuildConfigFromFlags: %w", err)
	}
	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("kubernetes.NewForConfig: %w", err)
	}
	return NewTestClusterWithClient(cluster, client), nil
}

// NewTestClusterWithClient returns a new TestCluster client with a given client.
func NewTestClusterWithClient(cluster *testpb.Cluster, client kubernetes.Interface) *TestCluster {
	return &TestCluster{
		cluster:                     cluster,
		client:                      client,
		testNodepoolRuntimeOverride: "",
	}
}

// Cluster returns the underlying cluster proto for tests.
func (t *TestCluster) Cluster() *testpb.Cluster {
	return t.cluster
}

// GetName returns this cluster's name.
func (t *TestCluster) GetName() string {
	return t.cluster.GetCluster().GetName()
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
	return t.client.CoreV1().Namespaces().Create(ctx, namespace, v1.CreateOptions{})
}

// getNamespace returns the given namespace in the cluster if it exists.
func (t *TestCluster) getNamespace(ctx context.Context, namespaceName string) (*v13.Namespace, error) {
	return t.client.CoreV1().Namespaces().Get(ctx, namespaceName, v1.GetOptions{})
}

// deleteNamespace is a helper method to delete a namespace.
func (t *TestCluster) deleteNamespace(ctx context.Context, namespaceName string) error {
	if err := t.client.CoreV1().Namespaces().Delete(ctx, namespaceName, v1.DeleteOptions{}); err != nil {
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

// ListNodes is a helper method to list nodes in a cluster.
func (t *TestCluster) ListNodes(ctx context.Context) (*v13.NodeList, error) {
	return t.client.CoreV1().Nodes().List(ctx, v1.ListOptions{})
}

// HasGVisorTestRuntime returns whether the test nodes in this cluster
// use the gVisor runtime.
func (t *TestCluster) HasGVisorTestRuntime(ctx context.Context) (bool, error) {
	nodes, err := t.ListNodes(ctx)
	if err != nil {
		return false, fmt.Errorf("cannot list nodes: %w", err)
	}
	var foundRuntime RuntimeType
	for _, n := range nodes.Items {
		if n.Labels[NodePoolTypeKey] != TestRuntimeNodepoolName {
			continue
		}
		nodeRuntime := RuntimeType(n.Labels[NodepoolRuntimeKey])
		if nodeRuntime == "" {
			return false, fmt.Errorf("node %q has no runtime label", n.GetName())
		}
		if foundRuntime == "" {
			foundRuntime = nodeRuntime
			continue
		}
		if nodeRuntime != foundRuntime {
			return false, fmt.Errorf("found conflicting runtimes in the same cluster: %q vs %q", foundRuntime, nodeRuntime)
		}
	}
	return foundRuntime == RuntimeTypeGVisor || foundRuntime == RuntimeTypeGVisorNvidia, nil
}

// CreatePod is a helper to create a pod.
func (t *TestCluster) CreatePod(ctx context.Context, pod *v13.Pod) (*v13.Pod, error) {
	if pod.GetObjectMeta().GetNamespace() == "" {
		pod.SetNamespace(NamespaceDefault)
	}
	return t.client.CoreV1().Pods(pod.GetNamespace()).Create(ctx, pod, v1.CreateOptions{})
}

// GetPod is a helper method to Get a pod's metadata.
func (t *TestCluster) GetPod(ctx context.Context, pod *v13.Pod) (*v13.Pod, error) {
	return t.client.CoreV1().Pods(pod.GetNamespace()).Get(ctx, pod.GetName(), v1.GetOptions{})
}

// ListPods is a helper method to List pods in a cluster.
func (t *TestCluster) ListPods(ctx context.Context, namespace string) (*v13.PodList, error) {
	return t.client.CoreV1().Pods(namespace).List(ctx, v1.ListOptions{})
}

// DeletePod is a helper method to delete a pod.
func (t *TestCluster) DeletePod(ctx context.Context, pod *v13.Pod) error {
	if err := t.client.CoreV1().Pods(pod.GetNamespace()).Delete(ctx, pod.GetName(), v1.DeleteOptions{}); err != nil {
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
	return t.client.CoreV1().Pods(pod.GetNamespace()).GetLogs(pod.GetName(), &opts).Stream(ctx)
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
	return t.doWaitForPod(ctx, pod, v13.PodRunning)
}

// WaitForPodCompleted is a helper method to wait for a pod to be completed.
func (t *TestCluster) WaitForPodCompleted(ctx context.Context, pod *v13.Pod) error {
	return t.doWaitForPod(ctx, pod, v13.PodSucceeded)
}

// doWaitForPod waits for a pod to complete based on a given v13.PodPhase.
func (t *TestCluster) doWaitForPod(ctx context.Context, pod *v13.Pod, phase v13.PodPhase) error {
	w, err := t.client.CoreV1().Pods(pod.GetNamespace()).Watch(ctx, v1.ListOptions{
		FieldSelector: fields.SelectorFromSet(fields.Set{v1.ObjectNameField: pod.GetName()}).String(),
	})
	if err != nil {
		return fmt.Errorf("watch: %w", err)
	}

	var p *v13.Pod
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-w.ResultChan():
			var ok bool
			p, ok = e.Object.(*v13.Pod)
			if !ok {
				return fmt.Errorf("invalid object watched: %T", p)
			}
		case <-time.After(10 * time.Second):
			p, err = t.GetPod(ctx, pod)
			if err != nil {
				return fmt.Errorf("failed to poll pod: %w", err)
			}
		}
		if ctx.Err() != nil {
			return fmt.Errorf("context expired waiting for pod %q failed: %s", pod.GetName(), ctx.Err())
		}
		if pod.Status.Reason == v13.PodReasonUnschedulable {
			return fmt.Errorf("pod %q failed: reason: %q message: %q", pod.GetName(), pod.Status.Reason, pod.Status.Message)
		}

		for _, c := range p.Status.Conditions {
			if strings.Contains(c.Reason, "Unschedulable") {
				return fmt.Errorf("pod %q failed: reason: %q message: %q", pod.GetName(), c.Reason, c.Message)
			}
		}

		switch p.Status.Phase {
		case v13.PodFailed:
			return fmt.Errorf("pod %q failed: %s", pod.GetName(), p.Status.Message)
		case phase:
			return nil
		}
	}
}

// RuntimeTestNodepoolIsARM returns true if the runtime undertest nodepool is an ARM nodepool.
func (t *TestCluster) RuntimeTestNodepoolIsARM() bool {
	np, err := t.getNodePoolByName(TestRuntimeNodepoolName)
	if err != nil {
		return false
	}
	return strings.HasPrefix(np.GetConfig().GetMachineType(), "t2a")
}

// configureDaemonSetForNodepool configures the DaemonSet to run on a given nodepool.
func (t *TestCluster) configureDaemonSetForNodepool(ds *appsv1.DaemonSet, nodepoolName string) error {
	np, err := t.getNodePoolByName(nodepoolName)
	if err != nil {
		return err
	}
	if ds.Labels == nil {
		ds.Labels = make(map[string]string)
	}
	return t.applyCommonPodConfigurations(np, &ds.Spec.Template.Spec)
}

// configurePodForNodepool configures the pod to run on a given nodepool.
func (t *TestCluster) configurePodForNodepool(pod *v13.Pod, nodepoolName string) (*v13.Pod, error) {
	np, err := t.getNodePoolByName(nodepoolName)
	if err != nil {
		return nil, err
	}
	if pod.Labels == nil {
		pod.Labels = make(map[string]string)
	}
	if err := t.applyCommonPodConfigurations(np, &pod.Spec); err != nil {
		return nil, err
	}
	return pod, nil
}

// ConfigureDaemonSetForRuntimeTestNodepool configures the DaemonSet to run
// on the test runtime.
func (t *TestCluster) ConfigureDaemonSetForRuntimeTestNodepool(ds *appsv1.DaemonSet) error {
	return t.configureDaemonSetForNodepool(ds, TestRuntimeNodepoolName)
}

// ConfigurePodForRuntimeTestNodepool configures the pod to run on the test runtime.
func (t *TestCluster) ConfigurePodForRuntimeTestNodepool(pod *v13.Pod) (*v13.Pod, error) {
	return t.configurePodForNodepool(pod, TestRuntimeNodepoolName)
}

// ConfigurePodForClientNodepool configures the pod to run on the client
// nodepool.
func (t *TestCluster) ConfigurePodForClientNodepool(pod *v13.Pod) (*v13.Pod, error) {
	return t.configurePodForNodepool(pod, ClientNodepoolName)
}

// ConfigurePodForTertiaryNodepool configures the pod to run on the tertiary
// nodepool.
func (t *TestCluster) ConfigurePodForTertiaryNodepool(pod *v13.Pod) (*v13.Pod, error) {
	return t.configurePodForNodepool(pod, TertiaryNodepoolName)
}

func (t *TestCluster) getNodePoolByName(name string) (*cspb.NodePool, error) {
	for _, np := range t.cluster.GetCluster().GetNodePools() {
		if np.GetName() == name {
			return np, nil
		}
	}
	return nil, fmt.Errorf("failed to find nodepool %q: %+v", name, t.cluster.GetCluster().GetNodePools())
}

func (t *TestCluster) applyCommonPodConfigurations(np *cspb.NodePool, podSpec *v13.PodSpec) error {
	// Apply GKE Sandbox configurations if the nodepool is a GKE Sandbox nodepool.
	if podSpec.NodeSelector == nil {
		podSpec.NodeSelector = make(map[string]string)
	}

	np.GetConfig().GetLabels()[NodePoolTypeKey] = np.GetName()

	// Force the pod to run on this nodepool.
	podSpec.NodeSelector[NodePoolSelectorKey] = np.GetName()

	// Figure out which runtime to use for this pod, either by flag override or
	// autodetection based on the nodepool configuration.
	var applyRuntime = RuntimeTypeUnsandboxed
	if np.GetName() == TestRuntimeNodepoolName && t.testNodepoolRuntimeOverride != "" {
		applyRuntime = t.testNodepoolRuntimeOverride
	} else if nodePoolRuntime, ok := np.GetConfig().GetLabels()[NodepoolRuntimeKey]; ok {
		applyRuntime = RuntimeType(nodePoolRuntime)
	}

	// Apply the runtime we've chosen, whether by override or autodetection.
	applyRuntime.ApplyPodSpec(podSpec)

	// If the nodepool has accelerators, copy the number of them as a node
	// selector option.
	// This doesn't really constrain the pod further, but allows
	// this number to be carried over when setting pod resources.
	if len(np.GetConfig().GetAccelerators()) > 0 {
		totalAccels := 0
		for _, accelCfg := range np.GetConfig().GetAccelerators() {
			totalAccels += int(accelCfg.GetAcceleratorCount())
		}
		if accelCount, ok := np.GetConfig().GetLabels()[NodepoolNumAcceleratorsKey]; !ok || accelCount != strconv.Itoa(totalAccels) {
			return fmt.Errorf("unexpected %s=%q label on nodepool with %d total accelerators", NodepoolNumAcceleratorsKey, accelCount, totalAccels)
		}
		podSpec.NodeSelector[NodepoolNumAcceleratorsKey] = strconv.Itoa(totalAccels)
	} else {
		for accelType, machineType := range TPUAcceleratorMachineTypeMap {
			if machineType == np.GetConfig().GetMachineType() {
				topology, ok := np.GetConfig().GetLabels()[NodepoolTPUTopologyKey]
				if !ok {
					return fmt.Errorf("unexpected %s=%q label on nodepool with no accelerators", NodepoolTPUTopologyKey, topology)
				}
				podSpec.NodeSelector[NodepoolTPUAcceleratorSelectorKey] = string(accelType)
				podSpec.NodeSelector[NodepoolTPUTopologySelectorKey] = np.GetConfig().GetLabels()[NodepoolTPUTopologyKey]
			}
		}
	}

	// If the nodepool is an ARM nodepool, apply ARM tolerations.
	for key, val := range np.GetConfig().GetLabels() {
		if key == archKey && val == armValue {
			podSpec.NodeSelector[archKey] = armValue
			podSpec.Tolerations = append(podSpec.Tolerations, v13.Toleration{
				Key:      archKey,
				Value:    armValue,
				Operator: v13.TolerationOpEqual,
				Effect:   v13.TaintEffectNoSchedule,
			})
		}
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
	return t.client.CoreV1().Services(service.GetNamespace()).Create(ctx, service, v1.CreateOptions{})
}

// ListServices is a helper method to List services in a cluster.
func (t *TestCluster) ListServices(ctx context.Context, namespace string) (*v13.ServiceList, error) {
	return t.client.CoreV1().Services(namespace).List(ctx, v1.ListOptions{})
}

// DeleteService is a helper to delete a given service.
func (t *TestCluster) DeleteService(ctx context.Context, service *v13.Service) error {
	if err := t.client.CoreV1().Services(service.GetNamespace()).Delete(ctx, service.GetName(), v1.DeleteOptions{}); err != nil {
		return err
	}
	// Wait for the service to disappear or for the context to expire.
	for ctx.Err() == nil {
		if _, err := t.client.CoreV1().Services(service.GetNamespace()).Get(ctx, service.GetName(), v1.GetOptions{}); err != nil {
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
	w, err := t.client.CoreV1().Services(service.GetNamespace()).Watch(ctx, v1.ListOptions{
		FieldSelector: fields.SelectorFromSet(fields.Set{v1.ObjectNameField: service.GetName()}).String(),
	})
	if err != nil {
		return fmt.Errorf("watch: %w", err)
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case e := <-w.ResultChan():
			s, ok := e.Object.(*v13.Service)
			if !ok {
				return fmt.Errorf("invalid object watched: %T", s)
			}
			if e.Type == watch.Added {
				return nil
			}
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
	return t.client.CoreV1().PersistentVolumeClaims(volume.GetNamespace()).Create(ctx, volume, v1.CreateOptions{})
}

// DeletePersistentVolume deletes a persistent volume.
func (t *TestCluster) DeletePersistentVolume(ctx context.Context, volume *v13.PersistentVolumeClaim) error {
	return t.client.CoreV1().PersistentVolumeClaims(volume.GetNamespace()).Delete(ctx, volume.GetName(), v1.DeleteOptions{})
}

// CreateDaemonset creates a daemonset with default options.
func (t *TestCluster) CreateDaemonset(ctx context.Context, ds *appsv1.DaemonSet) (*appsv1.DaemonSet, error) {
	if ds.GetObjectMeta().GetNamespace() == "" {
		ds.SetNamespace(NamespaceDefault)
	}
	return t.client.AppsV1().DaemonSets(ds.GetNamespace()).Create(ctx, ds, v1.CreateOptions{})
}

// DeleteDaemonset deletes a daemonset from this cluster.
func (t *TestCluster) DeleteDaemonset(ctx context.Context, ds *appsv1.DaemonSet) error {
	return t.client.AppsV1().DaemonSets(ds.GetNamespace()).Delete(ctx, ds.GetName(), v1.DeleteOptions{})
}

// GetPodsInDaemonSet returns the list of pods of the given DaemonSet.
func (t *TestCluster) GetPodsInDaemonSet(ctx context.Context, ds *appsv1.DaemonSet) ([]v13.Pod, error) {
	listOptions := v1.ListOptions{}
	if appLabel, found := ds.Spec.Template.Labels[k8sApp]; found {
		listOptions.LabelSelector = fmt.Sprintf("%s=%s", k8sApp, appLabel)
	}
	pods, err := t.client.CoreV1().Pods(ds.ObjectMeta.Namespace).List(ctx, listOptions)
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
	w, err := t.client.AppsV1().DaemonSets(ds.GetNamespace()).Watch(ctx, v1.ListOptions{
		FieldSelector: fields.SelectorFromSet(fields.Set{v1.ObjectNameField: ds.ObjectMeta.Name}).String(),
	})

	if err != nil {
		return fmt.Errorf("failed to watch daemon: %v", err)
	}
	defer w.Stop()
	var lastDS *appsv1.DaemonSet

	for daemonSetReady := false; !daemonSetReady; {
		select {
		case <-ctx.Done():
			if lastDS != nil {
				return fmt.Errorf("context canceled before healthy; last DaemonSet status: %#v", lastDS.Status)
			}
			return fmt.Errorf("context canceled before healthy")
		case e, ok := <-w.ResultChan():
			d, ok := e.Object.(*appsv1.DaemonSet)
			if !ok {
				return fmt.Errorf("invalid object type: %T", d)
			}
			lastDS = d
			if d.Status.NumberReady == d.Status.DesiredNumberScheduled && d.Status.DesiredNumberScheduled > 0 && d.Status.NumberUnavailable == 0 {
				daemonSetReady = true
			}
		}
	}

	// Now wait for the pods to be running.
	for ctx.Err() == nil {
		pods, err := t.GetPodsInDaemonSet(ctx, ds)
		if err != nil {
			return fmt.Errorf("failed to get pods in daemonset: %v", err)
		}
		if len(pods) == 0 {
			return fmt.Errorf("DaemonSet has no pods: %v", lastDS)
		}
		allOK := true
		for _, pod := range pods {
			switch pod.Status.Phase {
			case v13.PodRunning, v13.PodSucceeded:
				// OK, do nothing.
			default:
				allOK = false
			}
		}
		if allOK {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return nil
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
			logReader, err := t.client.CoreV1().Pods(pod.GetNamespace()).GetLogs(pod.GetName(), &opts).Stream(ctx)
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

	// Watch the DaemonSet.
	// We'll periodically refresh pods: either when the DaemonSet changes
	// state, or periodically every second.
	dsWatch, err := t.client.AppsV1().DaemonSets(ds.GetNamespace()).Watch(ctx, v1.ListOptions{
		FieldSelector: fields.SelectorFromSet(fields.Set{v1.ObjectNameField: ds.ObjectMeta.Name}).String(),
	})
	if err != nil {
		return fmt.Errorf("failed to watch DaemonSet: %v", err)
	}
	timeTicker := time.NewTicker(time.Second)
	defer timeTicker.Stop()
	defer dsWatch.Stop()

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
			if err := refreshPods(); err != nil {
				loopError = err
				break Outer
			}
		case e, ok := <-dsWatch.ResultChan():
			d, ok := e.Object.(*appsv1.DaemonSet)
			if !ok {
				loopError = fmt.Errorf("invalid object type: %T", d)
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
