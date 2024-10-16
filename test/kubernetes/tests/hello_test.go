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

package hello_test

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

// TestHello tests that a trivial alpine container runs correctly.
func TestHello(t *testing.T) {
	ctx := context.Background()
	k8sCtx, err := k8sctx.Context(ctx)
	if err != nil {
		t.Fatalf("Failed to get kubernetes context: %v", err)
	}
	cluster := k8sCtx.AcquireCluster(ctx, t)
	defer k8sCtx.ReleaseCluster(ctx, t, cluster)

	ns := cluster.Namespace(testcluster.NamespaceDefault)
	image, err := k8sCtx.ResolveImage(ctx, "alpine")
	if err != nil {
		t.Fatalf("Failed to resolve image: %v", err)
	}
	pod := ns.NewAlpinePod(fmt.Sprintf("hello-%d", time.Now().UnixNano()), image, []string{"/bin/sh", "-c", "echo hello"})
	pod, err = cluster.ConfigurePodForRuntimeTestNodepool(pod)
	if err != nil {
		t.Fatalf("Failed to set pod on cluster %q: %v", cluster.Cluster().GetCluster().GetName(), err)
	}
	pod, err = cluster.CreatePod(ctx, pod)
	if err != nil {
		t.Fatalf("Failed to create pod on cluster %q: %v", cluster.Cluster().GetCluster().GetName(), err)
	}
	defer cluster.DeletePod(ctx, pod)
	if err := cluster.WaitForPodCompleted(ctx, pod); err != nil {
		t.Fatalf("Failed to wait for pod on cluster %q: %v", cluster.Cluster().GetCluster().GetName(), err)
	}
	reader, err := cluster.GetLogReader(ctx, pod, v13.PodLogOptions{})
	if err != nil {
		t.Fatalf("Failed to get log reader on cluster %q: %v", cluster.Cluster().GetCluster().GetName(), err)
	}
	defer reader.Close()

	buf := new(bytes.Buffer)
	if _, err := io.Copy(buf, reader); err != nil {
		t.Fatalf("Failed to read log on cluster %q: %v", cluster.Cluster().GetCluster().GetName(), err)
	}
	if strings.TrimSpace(buf.String()) != "hello" {
		t.Fatalf("Mistmatch output: got: %q want: %q", buf.String(), "hello")
	}
}

func TestMain(m *testing.M) {
	k8sctx.TestMain(m, map[string]k8sctx.TestFunc{
		"TestHello": TestHello,
	})
}
