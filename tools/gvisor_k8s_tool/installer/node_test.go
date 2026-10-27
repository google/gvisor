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
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
)

func TestInstallerPodEventNamespaceAndReference(t *testing.T) {
	client := fake.NewClientset()
	cfg := Config{
		NodeName:  "worker",
		Namespace: "installer-namespace",
		PodName:   "installer-pod",
		PodUID:    "pod-uid",
	}
	node := NewNodeClient(client, cfg, discardLogger{})
	node.Event(corev1.EventTypeNormal, "GVisorReady", "available")
	events, err := client.CoreV1().Events(cfg.Namespace).List(t.Context(), metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(events.Items) != 1 {
		t.Fatalf("got %d events", len(events.Items))
	}
	event := events.Items[0]
	if event.Namespace != cfg.Namespace || event.InvolvedObject.Kind != "Pod" || event.InvolvedObject.Name != cfg.PodName || event.InvolvedObject.UID != types.UID(cfg.PodUID) || event.InvolvedObject.Namespace != cfg.Namespace {
		t.Fatalf("incorrect event reference %+v", event)
	}
}
