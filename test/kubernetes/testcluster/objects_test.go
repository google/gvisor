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

package testcluster

import (
	"testing"

	v23 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

func TestGetPersistentVolume(t *testing.T) {
	ns := &Namespace{
		Namespace: "test-ns",
	}

	testCases := []struct {
		name string
		size string
	}{
		{
			name: "test-pv-1",
			size: "1Gi",
		},
		{
			name: "test-pv-2",
			size: "10Gi",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pvc := ns.GetPersistentVolume(tc.name, tc.size)

			if pvc.ObjectMeta.Name != tc.name {
				t.Errorf("expected name %q, got %q", tc.name, pvc.ObjectMeta.Name)
			}

			if pvc.ObjectMeta.Namespace != ns.Namespace {
				t.Errorf("expected namespace %q, got %q", ns.Namespace, pvc.ObjectMeta.Namespace)
			}

			// Verify size.
			requests := pvc.Spec.Resources.Requests
			if requests == nil {
				t.Fatalf("expected Spec.Resources.Requests to be set, but it was nil")
			}

			storage, ok := requests[v23.ResourceStorage]
			if !ok {
				t.Fatalf("expected storage request to be set")
			}

			expectedSize := resource.MustParse(tc.size)
			if !storage.Equal(expectedSize) {
				t.Errorf("expected storage size %v, got %v", expectedSize, storage)
			}
		})
	}
}
