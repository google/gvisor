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

package control

import (
	"testing"

	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
)

func TestCudaCheckpointDeviceMap(t *testing.T) {
	const (
		uuidA = "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
		uuidB = "GPU-bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
		uuidC = "GPU-cccccccc-cccc-cccc-cccc-cccccccccccc"
	)
	id := func(minor uint32, uuid string) nvproxy.DeviceRemapID {
		return nvproxy.DeviceRemapID{Minor: minor, DeviceInstance: minor, UUID: uuid}
	}
	for _, tc := range []struct {
		name    string
		oldIDs  []nvproxy.DeviceRemapID
		newIDs  []nvproxy.DeviceRemapID
		want    string
		wantErr bool
	}{
		{
			name:   "identity",
			oldIDs: []nvproxy.DeviceRemapID{id(0, uuidA), id(1, uuidB)},
			newIDs: []nvproxy.DeviceRemapID{id(0, uuidA), id(1, uuidB)},
			want:   "",
		},
		{
			name:   "single device",
			oldIDs: []nvproxy.DeviceRemapID{id(0, uuidA)},
			newIDs: []nvproxy.DeviceRemapID{id(1, uuidB)},
			want:   uuidA + "=" + uuidB,
		},
		{
			// Only one device moves, but all checkpointed devices must be
			// listed, ordered by old minor.
			name:   "partial remap",
			oldIDs: []nvproxy.DeviceRemapID{id(1, uuidB), id(0, uuidA)},
			newIDs: []nvproxy.DeviceRemapID{id(2, uuidC), id(0, uuidA)},
			want:   uuidA + "=" + uuidA + "," + uuidB + "=" + uuidC,
		},
		{
			name:    "missing UUID",
			oldIDs:  []nvproxy.DeviceRemapID{id(0, uuidA)},
			newIDs:  []nvproxy.DeviceRemapID{id(1, "")},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dr, err := nvproxy.MakeDeviceRemapping(tc.oldIDs, tc.newIDs)
			if err != nil {
				t.Fatalf("MakeDeviceRemapping failed: %v", err)
			}
			got, err := cudaCheckpointDeviceMap(dr)
			if (err != nil) != tc.wantErr {
				t.Fatalf("cudaCheckpointDeviceMap() error = %v, wantErr %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("cudaCheckpointDeviceMap() = %q, want %q", got, tc.want)
			}
		})
	}
}
