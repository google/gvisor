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

package hello

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"gvisor.dev/gvisor/test/kubernetes/k8sctx"
	"gvisor.dev/gvisor/test/kubernetes/testcluster"
	v13 "k8s.io/api/core/v1"
)

// RunHello tests that a trivial alpine container runs correctly.
func RunHello(ctx context.Context, t *testing.T, k8sCtx k8sctx.KubernetesContext, cluster *testcluster.TestCluster) {
	ns := cluster.Namespace(testcluster.NamespaceDefault)
	image, err := k8sCtx.ResolveImage(ctx, "alpine")
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}
	pod := ns.NewAlpinePod(fmt.Sprintf("hello-%d", time.Now().UnixNano()), image, []string{"/bin/sh", "-c", "echo hello"})
	pod, err = cluster.ConfigurePodForRuntimeTestNodepool(ctx, pod)
	if err != nil {
		t.Fatalf("Failed to set pod on cluster %q: %v", cluster.GetName(), err)
	}
	pod, err = cluster.CreatePod(ctx, pod)
	if err != nil {
		t.Fatalf("Failed to create pod on cluster %q: %v", cluster.GetName(), err)
	}
	defer cluster.DeletePod(ctx, pod)
	if err := cluster.WaitForPodCompleted(ctx, pod); err != nil {
		t.Fatalf("Failed to wait for pod on cluster %q: %v", cluster.GetName(), err)
	}
	reader, err := cluster.GetLogReader(ctx, pod, v13.PodLogOptions{})
	if err != nil {
		t.Fatalf("Failed to get log reader on cluster %q: %v", cluster.GetName(), err)
	}
	defer reader.Close()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, reader); err != nil {
		t.Fatalf("Failed to read log on cluster %q: %v", cluster.GetName(), err)
	}
	if strings.TrimSpace(buf.String()) != "hello" {
		t.Fatalf("Mismatch output: got: %q want: %q", buf.String(), "hello")
	}
}
