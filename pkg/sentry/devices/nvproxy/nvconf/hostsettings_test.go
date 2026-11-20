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

package nvconf

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func writeMIGFixture(t *testing.T, root, path, contents string) {
	t.Helper()
	path = filepath.Join(root, path)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		t.Fatal(err)
	}
}

const migMinorsIndex = "nvidia-caps/mig-minors"

func TestMIGCapabilitiesGrantedInstancesOnly(t *testing.T) {
	root := t.TempDir()
	writeMIGFixture(t, root, migMinorsIndex, "config 1\nmonitor 2\ngpu0/gi7/access 21\ngpu0/gi7/ci0/access 22\ngpu0/gi8/access 23\ngpu1/gi0/access 24\ngpuX/gi7/access 25\ngpu0/gi7evil/access 26\n")
	for path, contents := range map[string]string{
		"capabilities/gpu0/mig/gi7/access":     "DeviceFileMinor: 21\nDeviceFileMode: 256\nDeviceFileModify: 1\n",
		"capabilities/gpu0/mig/gi7/ci0/access": "DeviceFileMinor: 22\nDeviceFileMode: 256\n",
		"capabilities/gpu0/mig/gi8/access":     "DeviceFileMinor: 23\nDeviceFileMode: 256\n",
		"capabilities/gpu1/mig/gi0/access":     "DeviceFileMinor: 24\nDeviceFileMode: 256\n",
		"capabilities/mig/config":              "DeviceFileMinor: 1\nDeviceFileMode: 256\n",
		"capabilities/mig/monitor":             "DeviceFileMinor: 2\nDeviceFileMode: 292\n",
		"capabilities/gpuX/mig/gi7/access":     "invalid",
		"capabilities/gpu0/mig/gi7evil/access": "invalid",
	} {
		writeMIGFixture(t, root, "nvidia/"+path, contents)
	}
	got, err := getMIGCapabilities(root, []uint32{1, 2, 21, 22, 25, 26, 99})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]MIGCapability{
		"capabilities/gpu0/mig/gi7/access":     {Minor: 21, Mode: 256},
		"capabilities/gpu0/mig/gi7/ci0/access": {Minor: 22, Mode: 256},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("capabilities = %v, want %v", got, want)
	}
}

func TestMIGCapabilitiesRejectMalformedMetadata(t *testing.T) {
	for _, contents := range []string{
		"DeviceFileMode: 256\n",
		"DeviceFileMinor: 4294967296\nDeviceFileMode: 256\n",
		"DeviceFileMinor: 3\n",
		"DeviceFileMinor: 3\nDeviceFileMode: 4095\n",
		"DeviceFileMinor: 3\nDeviceFileMode: 256\nDeviceFileMinor: 4\n",
		"DeviceFileMinor: 4\nDeviceFileMode: 256\n",
	} {
		t.Run(contents, func(t *testing.T) {
			root := t.TempDir()
			writeMIGFixture(t, root, migMinorsIndex, "gpu0/gi0/access 3\n")
			writeMIGFixture(t, root, "nvidia/capabilities/gpu0/mig/gi0/access", contents)
			if _, err := getMIGCapabilities(root, []uint32{3}); err == nil {
				t.Fatal("accepted malformed capability metadata")
			}
		})
	}
}

func TestMIGCapabilitiesMissingAccessRecord(t *testing.T) {
	const (
		assignedGI  = "capabilities/gpu0/mig/gi7/access"
		assignedCI  = "capabilities/gpu0/mig/gi7/ci0/access"
		unrelatedGI = "capabilities/gpu0/mig/gi9/access"
	)

	for _, missing := range []string{unrelatedGI, assignedGI, assignedCI} {
		t.Run(missing, func(t *testing.T) {
			root := t.TempDir()
			writeMIGFixture(t, root, migMinorsIndex, "gpu0/gi7/access 66\ngpu0/gi7/ci0/access 67\ngpu0/gi9/access 84\n")
			records := map[string]MIGCapability{
				assignedGI:  {Minor: 66, Mode: 0444},
				assignedCI:  {Minor: 67, Mode: 0444},
				unrelatedGI: {Minor: 84, Mode: 0444},
			}
			for path, record := range records {
				fullPath := filepath.Join(root, "nvidia", path)
				if path == missing {
					// Leave a directory entry whose target cannot be opened.
					// This models a record disappearing after enumeration.
					if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink("missing", fullPath); err != nil {
						t.Fatal(err)
					}
					continue
				}
				writeMIGFixture(t, root, "nvidia/"+path, fmt.Sprintf("DeviceFileMinor: %d\nDeviceFileMode: %d\n", record.Minor, record.Mode))
			}
			got, err := getMIGCapabilities(root, []uint32{66, 67})
			if missing == unrelatedGI {
				delete(records, unrelatedGI)
				if err != nil || !reflect.DeepEqual(got, records) {
					t.Errorf("capabilities = %v, %v; want %v", got, err, records)
				}
				return
			}
			wantError := fmt.Sprintf("assigned MIG capability minor %d", records[missing].Minor)
			if got != nil || !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), wantError) || !strings.Contains(err.Error(), missing) {
				t.Errorf("capabilities = %v, %v; want no capabilities and missing-record error for %s", got, err, missing)
			}
		})
	}
}

func TestMIGCapabilitiesMissingIndex(t *testing.T) {
	got, err := getMIGCapabilities(t.TempDir(), []uint32{3})
	if err != nil || len(got) != 0 {
		t.Errorf("capabilities = %v, %v; want empty map", got, err)
	}
}
