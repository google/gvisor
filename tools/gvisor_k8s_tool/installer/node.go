// Copyright The Isola Authors
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

package installer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes"
)

// LabelGVisorReady gates scheduling: the RuntimeClass selects on it, so
// sandbox pods only land on nodes with a verified-healthy runtime.
const (
	LabelGVisorReady   = "gvisor.dev/ready"
	LabelGVisorVersion = "gvisor.dev/version"

	// Per-node opt-out, enforced by the DaemonSet's node affinity in the Helm
	// template, not here.
	LabelGVisorInstall = "gvisor.dev/install"
)

type NodeClient interface {
	// An empty value removes the label.
	SetNodeLabels(ctx context.Context, labels map[string]string) error
	Event(eventType, reason, message string)
}

type nodeClient struct {
	clientset kubernetes.Interface
	nodeName  string
	namespace string
	podName   string
	podUID    string
	log       Logger
}

func NewNodeClient(clientset kubernetes.Interface, cfg Config, logger Logger) NodeClient {
	return &nodeClient{
		clientset: clientset,
		nodeName:  cfg.NodeName,
		namespace: cfg.Namespace,
		podName:   cfg.PodName,
		podUID:    cfg.PodUID,
		log:       logger,
	}
}

func (n *nodeClient) SetNodeLabels(ctx context.Context, labels map[string]string) error {
	// Strategic-merge semantics on labels: null deletes the key.
	patchLabels := make(map[string]*string, len(labels))
	for k, v := range labels {
		if v == "" {
			patchLabels[k] = nil
		} else {
			patchLabels[k] = &v
		}
	}
	patch, err := json.Marshal(map[string]any{"metadata": map[string]any{"labels": patchLabels}})
	if err != nil {
		return err
	}
	if _, err := n.clientset.CoreV1().Nodes().Patch(ctx, n.nodeName, types.StrategicMergePatchType, patch, metav1.PatchOptions{}); err != nil {
		return fmt.Errorf("patching node labels: %w", err)
	}
	return nil
}

func (n *nodeClient) Event(eventType, reason, message string) {
	// An unavailable Kubernetes API must not leave the installer waiting
	// indefinitely just to report an event.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	now := metav1.Now()
	event := &corev1.Event{
		ObjectMeta: metav1.ObjectMeta{GenerateName: n.nodeName + ".", Namespace: n.namespace},
		InvolvedObject: corev1.ObjectReference{
			APIVersion: "v1",
			Kind:       "Pod",
			Name:       n.podName,
			Namespace:  n.namespace,
			UID:        types.UID(n.podUID),
		},
		Type:           eventType,
		Reason:         reason,
		Message:        message,
		FirstTimestamp: now,
		LastTimestamp:  now,
		Count:          1,
		Source:         corev1.EventSource{Component: "gvisor-node-installer", Host: n.nodeName},
	}
	if _, err := n.clientset.CoreV1().Events(n.namespace).Create(ctx, event, metav1.CreateOptions{}); err != nil {
		n.log.Warn("recording installer event failed", "error", err)
	}
}
