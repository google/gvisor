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
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type testRuntimeServer struct {
	runtimeapi.UnimplementedRuntimeServiceServer
}

func (testRuntimeServer) ListPodSandbox(context.Context, *runtimeapi.ListPodSandboxRequest) (*runtimeapi.ListPodSandboxResponse, error) {
	return &runtimeapi.ListPodSandboxResponse{Items: []*runtimeapi.PodSandbox{
		{Id: "installer", State: runtimeapi.PodSandboxState_SANDBOX_READY, Metadata: &runtimeapi.PodSandboxMetadata{Uid: "installer-uid"}},
		{Id: "old", State: runtimeapi.PodSandboxState_SANDBOX_NOTREADY, Metadata: &runtimeapi.PodSandboxMetadata{Uid: "stopped-uid"}},
	}}, nil
}
func (testRuntimeServer) Status(_ context.Context, req *runtimeapi.StatusRequest) (*runtimeapi.StatusResponse, error) {
	response := &runtimeapi.StatusResponse{Status: &runtimeapi.RuntimeStatus{Conditions: []*runtimeapi.RuntimeCondition{{Type: runtimeapi.RuntimeReady, Status: true}}}}
	if req.Verbose {
		response.Info = map[string]string{"config": `{"containerd":{"runtimes":{"runsc":{"runtimeType":"io.containerd.runsc.v1","runtimePath":"/opt/gvisor/shim","options":{"TypeUrl":"io.containerd.runsc.v1.options","ConfigPath":"/opt/gvisor/config.toml"}}}}}`}
	}
	return response, nil
}
func TestCRIConnectionChecksPeerAndInstallerSandbox(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "cri.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	runtimeapi.RegisterRuntimeServiceServer(server, &testRuntimeServer{})
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	client := NewCRIClient(socket)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := client.VerifyIdentity(ctx, os.Getpid(), "installer-uid"); err != nil {
		t.Fatal(err)
	}
	status, err := client.Status(ctx, true)
	if err != nil {
		t.Fatal(err)
	}
	if !status.RuntimeReady || status.Runtimes["runsc"].OptionsTypeURL != runscOptionsTypeURL {
		t.Fatalf("invalid status %+v", status)
	}
	for _, uid := range []string{"missing-uid", "stopped-uid"} {
		if err := client.VerifyIdentity(ctx, os.Getpid(), uid); err == nil {
			t.Fatalf("accepted sandbox %q", uid)
		}
	}
	shortCtx, shortCancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer shortCancel()
	if err := client.VerifyIdentity(shortCtx, os.Getpid()+1, "installer-uid"); err == nil {
		t.Fatal("accepted CRI socket from wrong process")
	}
	// Status creates another connection and must enforce the same peer identity.
	if _, err := client.Status(shortCtx, true); err == nil {
		t.Fatal("status connection bypassed socket peer identity")
	}
}

func TestRuntimesFromPluginConfig(t *testing.T) {
	for _, raw := range []string{`{`, `{"containerd":{"runtimes":[]} }`} {
		if _, err := runtimesFromPluginConfig(raw); err == nil {
			t.Fatalf("malformed CRI config accepted: %s", raw)
		}
	}
	config := map[string]any{"containerd": map[string]any{"runtimes": map[string]any{"runsc": map[string]any{"runtimeType": runscRuntimeType, "runtimePath": "/shim", "options": map[string]any{"ConfigPath": "/config", "TypeUrl": runscOptionsTypeURL}}}}}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	runtimes, err := runtimesFromPluginConfig(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if runtimes["runsc"].ConfigPath != "/config" || runtimes["runsc"].OptionsTypeURL != runscOptionsTypeURL {
		t.Fatalf("incorrect loaded config %+v", runtimes)
	}
}

func TestCRIUnavailableWhenPeerHasNoRuntimeService(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "no-cri.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)
	client := NewCRIClient(socket)
	err = client.VerifyIdentity(t.Context(), os.Getpid(), "installer-uid")
	if !errors.Is(err, errCRIUnavailable) {
		t.Fatalf("missing RuntimeService did not classify as unavailable: %v", err)
	}
	if _, err := client.Status(t.Context(), true); !errors.Is(err, errCRIUnavailable) {
		t.Fatalf("missing RuntimeService status did not classify as unavailable: %v", err)
	}
	mismatchCtx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()
	if err := client.VerifyIdentity(mismatchCtx, os.Getpid()+1, "installer-uid"); !errors.Is(err, errIdentityMismatch) || errors.Is(err, errCRIUnavailable) {
		t.Fatalf("peer mismatch did not take precedence over missing RuntimeService: %v", err)
	}
}
