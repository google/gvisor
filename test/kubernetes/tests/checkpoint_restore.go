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

// Package checkpointrestore tests Kubernetes-driven checkpoint/restore.
package checkpointrestore

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes"
)

const (
	checkpointRestoreNamespace = "checkpoint-restore"
	checkpointRestoreContainer = "server"
	checkpointRestorePort      = 8000
	checkpointHostPathAnno     = "dev.gvisor.internal.restore.host-image-path"
)

var (
	checkpointPathRE = regexp.MustCompile(`/var/lib/criu-dumps/runsc-[A-Za-z0-9_.:-]+`)
	serverStateRE    = regexp.MustCompile(`token=([^ ]+) started=([^ ]+) counter=([0-9]+)`)
)

type serverState struct {
	token   string
	started string
	counter int
}

// RunCheckpointRestore tests checkpoint/restore via Kubernetes kubelet APIs.
func RunCheckpointRestore(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
	hasGVisor, err := cluster.HasGVisorTestRuntime(ctx)
	if err != nil {
		t.Fatalf("Failed to determine runtime for cluster %q: %v", cluster.GetName(), err)
	}
	if !hasGVisor {
		t.Skipf("checkpoint restore test requires a gVisor test runtime")
	}

	ns := cluster.Namespace(checkpointRestoreNamespace)
	if err := ns.Reset(ctx); err != nil {
		t.Fatalf("Failed to reset namespace %q: %v", checkpointRestoreNamespace, err)
	}
	defer ns.Cleanup(ctx)

	serverImage, err := k8sCtx.ResolveImage(ctx, "python:3.12-alpine")
	if err != nil {
		t.Fatalf("Failed to resolve server image: %v", err)
	}
	clientImage, err := k8sCtx.ResolveImage(ctx, "alpine")
	if err != nil {
		t.Fatalf("Failed to resolve client image: %v", err)
	}

	token := fmt.Sprintf("checkpoint-restore-%d", time.Now().UnixNano())
	service := checkpointRestoreService(ns)
	if _, err := cluster.CreateService(ctx, service); err != nil {
		t.Fatalf("Failed to create service: %v", err)
	}
	defer cluster.DeleteService(ctx, service)

	sourcePod, err := cluster.ConfigurePodForRuntimeTestNodepool(ctx, checkpointRestoreServerPod(ns, "checkpoint-source", serverImage, token))
	if err != nil {
		t.Fatalf("Failed to configure source pod: %v", err)
	}
	sourcePod, err = cluster.CreatePod(ctx, sourcePod)
	if err != nil {
		t.Fatalf("Failed to create source pod: %v", err)
	}
	defer cluster.DeletePod(ctx, sourcePod)
	if err := cluster.WaitForPodRunning(ctx, sourcePod); err != nil {
		t.Fatalf("Failed to wait for source pod: %v", err)
	}
	sourcePod, err = cluster.GetPod(ctx, sourcePod)
	if err != nil {
		t.Fatalf("Failed to refresh source pod: %v", err)
	}
	if sourcePod.Spec.NodeName == "" {
		t.Fatalf("Source pod has no assigned node: %+v", sourcePod)
	}

	sourceState := requestCheckpointServer(ctx, t, cluster, service, clientImage, "checkpoint-source-client")
	t.Logf("Source server state before checkpoint: %+v", sourceState)

	checkpointResponse, err := checkpointContainer(ctx, cluster, sourcePod)
	if err != nil {
		t.Fatalf("Failed to checkpoint source pod: %v", err)
	}
	t.Logf("Kubelet checkpoint response: %q", strings.TrimSpace(checkpointResponse))
	checkpointPath := checkpointPathFromResponse(checkpointResponse)
	if checkpointPath == "" {
		checkpointPath = latestCheckpointHostPath(ctx, t, cluster, ns, clientImage, sourcePod.Spec.NodeName)
	}
	defer cleanupCheckpointHostPath(ctx, t, cluster, ns, clientImage, sourcePod.Spec.NodeName, checkpointPath)
	t.Logf("Restoring from checkpoint host path: %s", checkpointPath)

	if err := cluster.DeletePod(ctx, sourcePod); err != nil {
		t.Fatalf("Failed to delete source pod before restore: %v", err)
	}

	restorePod := checkpointRestoreServerPod(ns, "checkpoint-restored", serverImage, token)
	restorePod.ObjectMeta.Annotations = map[string]string{
		checkpointHostPathAnno: checkpointPath,
	}
	restorePod.Spec.NodeName = sourcePod.Spec.NodeName
	restorePod, err = cluster.ConfigurePodForRuntimeTestNodepool(ctx, restorePod)
	if err != nil {
		t.Fatalf("Failed to configure restore pod: %v", err)
	}
	restorePod.Spec.NodeName = sourcePod.Spec.NodeName
	restorePod, err = cluster.CreatePod(ctx, restorePod)
	if err != nil {
		t.Fatalf("Failed to create restore pod: %v", err)
	}
	defer cluster.DeletePod(ctx, restorePod)
	if err := cluster.WaitForPodRunning(ctx, restorePod); err != nil {
		t.Fatalf("Failed to wait for restore pod: %v", err)
	}

	restoreState := requestCheckpointServer(ctx, t, cluster, service, clientImage, "checkpoint-restore-client")
	t.Logf("Restored server state: %+v", restoreState)
	if restoreState.token != sourceState.token {
		t.Fatalf("Restored server token mismatch: got %q, want %q", restoreState.token, sourceState.token)
	}
	if restoreState.started != sourceState.started {
		t.Fatalf("Restored server restarted instead of resuming: got start %q, want %q", restoreState.started, sourceState.started)
	}
	if restoreState.counter <= sourceState.counter {
		t.Fatalf("Restored server counter did not advance: got %d, want > %d", restoreState.counter, sourceState.counter)
	}
}

func checkpointRestoreServerPod(ns *testcluster.Namespace, name, image, token string) *v13.Pod {
	pod := ns.NewPod(name)
	pod.ObjectMeta.Labels = map[string]string{
		"app": "checkpoint-restore",
	}
	pod.Spec.Containers = []v13.Container{
		{
			Name:  checkpointRestoreContainer,
			Image: image,
			Env: []v13.EnvVar{
				{Name: "TOKEN", Value: token},
			},
			Command: []string{"python3", "-u", "-c", checkpointRestoreServerScript},
			Ports: []v13.ContainerPort{
				{ContainerPort: checkpointRestorePort},
			},
		},
	}
	return pod
}

func checkpointRestoreService(ns *testcluster.Namespace) *v13.Service {
	return ns.GetService("checkpoint-restore", v13.ServiceSpec{
		Selector: map[string]string{
			"app": "checkpoint-restore",
		},
		Ports: []v13.ServicePort{
			{
				Port:       checkpointRestorePort,
				TargetPort: intstr.FromInt(checkpointRestorePort),
			},
		},
	})
}

const checkpointRestoreServerScript = `
import http.server
import os
import socketserver
import time

token = os.environ["TOKEN"]
started = str(time.time_ns())
counter = 0

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        global counter
        counter += 1
        body = f"token={token} started={started} counter={counter}\n".encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return

socketserver.TCPServer(("0.0.0.0", 8000), Handler).serve_forever()
`

func checkpointContainer(ctx context.Context, cluster *testcluster.TestCluster, pod *v13.Pod) (string, error) {
	var response []byte
	if err := cluster.Do(ctx, func(ctx context.Context, client kubernetes.Interface) error {
		result := client.CoreV1().RESTClient().Post().
			Resource("nodes").
			Name(pod.Spec.NodeName).
			SubResource("proxy").
			Suffix("checkpoint", pod.Namespace, pod.Name, checkpointRestoreContainer).
			Do(ctx)
		var err error
		response, err = result.Raw()
		return err
	}); err != nil {
		return "", err
	}
	return string(response), nil
}

func checkpointPathFromResponse(response string) string {
	return checkpointPathRE.FindString(response)
}

func requestCheckpointServer(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster, service *v13.Service, clientImage, clientPodName string) serverState {
	t.Helper()
	var lastErr error
	for ctx.Err() == nil {
		out, err := cluster.ExecRequestInClientPod(ctx, service, service.Namespace, clientImage, clientPodName, func(hostPort string) []string {
			return []string{"/bin/sh", "-c", fmt.Sprintf("wget -qO- --timeout=5 --tries=1 %s", hostPort)}
		})
		if err == nil {
			state, parseErr := parseServerState(string(out))
			if parseErr == nil {
				return state
			}
			lastErr = parseErr
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
		case <-time.After(time.Second):
		}
	}
	t.Fatalf("Failed to request checkpoint server: %v", lastErr)
	return serverState{}
}

func parseServerState(response string) (serverState, error) {
	match := serverStateRE.FindStringSubmatch(strings.TrimSpace(response))
	if match == nil {
		return serverState{}, fmt.Errorf("unexpected server response %q", response)
	}
	counter, err := strconv.Atoi(match[3])
	if err != nil {
		return serverState{}, fmt.Errorf("failed to parse counter %q: %w", match[3], err)
	}
	return serverState{token: match[1], started: match[2], counter: counter}, nil
}

func latestCheckpointHostPath(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster, ns *testcluster.Namespace, image, nodeName string) string {
	t.Helper()
	out := runHostCommand(ctx, t, cluster, ns, image, nodeName, "checkpoint-path", `
set -eu
latest=""
for d in /host/var/lib/criu-dumps/runsc-*; do
  [ -f "$d/checkpoint.img" ] || continue
  latest="${d#/host}"
done
[ -n "$latest" ]
printf "%s\n" "$latest"
`)
	checkpointPath := strings.TrimSpace(out)
	if checkpointPathFromResponse(checkpointPath) != checkpointPath {
		t.Fatalf("Host helper returned invalid checkpoint path %q", checkpointPath)
	}
	return checkpointPath
}

func cleanupCheckpointHostPath(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster, ns *testcluster.Namespace, image, nodeName, checkpointPath string) {
	t.Helper()
	if checkpointPathFromResponse(checkpointPath) != checkpointPath {
		t.Logf("Skipping cleanup for invalid checkpoint path %q", checkpointPath)
		return
	}
	_ = runHostCommand(ctx, t, cluster, ns, image, nodeName, "checkpoint-cleanup", fmt.Sprintf("rm -rf -- /host%s", checkpointPath))
}

func runHostCommand(ctx context.Context, t *testing.T, cluster *testcluster.TestCluster, ns *testcluster.Namespace, image, nodeName, nameSuffix, command string) string {
	t.Helper()
	name := fmt.Sprintf("host-%s-%d", nameSuffix, time.Now().UnixNano())
	pod := ns.NewPod(name)
	pod.Spec.NodeName = nodeName
	pod.Spec.RuntimeClassName = nil
	pod.Spec.HostPID = true
	pod.Spec.HostNetwork = true
	pod.Spec.Tolerations = []v13.Toleration{
		cluster.GetGVisorRuntimeToleration(),
		{Operator: v13.TolerationOpExists},
	}
	pod.Spec.Volumes = []v13.Volume{
		{
			Name: "host",
			VolumeSource: v13.VolumeSource{
				HostPath: &v13.HostPathVolumeSource{Path: "/"},
			},
		},
	}
	pod.Spec.Containers = []v13.Container{
		{
			Name:            "host",
			Image:           image,
			Command:         []string{"/bin/sh", "-c", command},
			SecurityContext: &v13.SecurityContext{Privileged: proto.Bool(true)},
			VolumeMounts: []v13.VolumeMount{
				{Name: "host", MountPath: "/host"},
			},
		},
	}
	pod.ObjectMeta = v1.ObjectMeta{
		Name:      name,
		Namespace: ns.Namespace,
	}
	pod, err := cluster.CreatePod(ctx, pod)
	if err != nil {
		t.Fatalf("Failed to create host helper pod: %v", err)
	}
	defer cluster.DeletePod(ctx, pod)
	if err := cluster.WaitForPodCompleted(ctx, pod); err != nil {
		t.Fatalf("Host helper pod failed: %v", err)
	}
	logs, err := cluster.ReadPodLogs(ctx, pod)
	if err != nil {
		t.Fatalf("Failed to read host helper logs: %v", err)
	}
	return logs
}
