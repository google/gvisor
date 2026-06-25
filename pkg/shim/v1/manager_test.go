// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1

import (
	"bytes"
	"context"
	"testing"

	typeurl "github.com/containerd/typeurl/v2"
	"github.com/opencontainers/runtime-spec/specs-go/features"

	"gvisor.dev/gvisor/runsc/specutils"
)

// TestResolveGrouping verifies that resolveGrouping correctly extracts the
// sandbox ID from both containerd and CRI-O annotations.
func TestResolveGrouping(t *testing.T) {
	const containerID = "test-container-id"
	const sandboxID = "test-sandbox-id"

	for _, tc := range []struct {
		name        string
		annotations map[string]string
		want        string
	}{
		{
			name:        "containerd annotation",
			annotations: map[string]string{kubernetesGroupAnnotation: sandboxID},
			want:        sandboxID,
		},
		{
			name:        "crio annotation",
			annotations: map[string]string{specutils.CRIOSandboxIDAnnotation: sandboxID},
			want:        sandboxID,
		},
		{
			name: "containerd takes precedence over crio",
			annotations: map[string]string{
				kubernetesGroupAnnotation:            "containerd-sandbox",
				specutils.CRIOSandboxIDAnnotation:    "crio-sandbox",
			},
			want: "containerd-sandbox",
		},
		{
			name:        "no annotation returns container ID",
			annotations: map[string]string{},
			want:        containerID,
		},
		{
			name:        "nil annotations returns container ID",
			annotations: nil,
			want:        containerID,
		},
		{
			name:        "unrelated annotations returns container ID",
			annotations: map[string]string{"io.kubernetes.cri-o.ContainerType": "container"},
			want:        containerID,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveGrouping(containerID, tc.annotations)
			if got != tc.want {
				t.Errorf("resolveGrouping(%q, %v) = %q, want %q", containerID, tc.annotations, got, tc.want)
			}
		})
	}
}

// TestManagerInfo verifies that the Info() call returns the expected information
// about the runtime.
func TestManagerInfo(t *testing.T) {
	m := NewShimManager("io.containerd.runsc.v1")
	info, err := m.Info(context.Background(), bytes.NewReader(nil))
	if err != nil {
		t.Fatalf("Standalone ShimManager::Info call returned unexpected error: %v", err)
	}
	if info == nil {
		t.Fatalf("ShimManager::Info got nil, want non-nil RuntimeInfo")
	}
	if info.Features == nil {
		t.Fatalf("ShimManager::Info got nil, want populated Features struct from specutils")
	}

	decoded, err := typeurl.UnmarshalAny(info.Features)
	if err != nil {
		t.Fatalf("Failed to deserialize info.Features Any proto: %v", err)
	}

	_, ok := decoded.(*features.Features)
	if !ok {
		t.Fatalf("Decoded features is type %T, want *features.Features", decoded)
	}

}
