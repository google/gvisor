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
	"os"
	"path/filepath"
	"reflect"
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

func TestMIGCapabilitiesGrantedInstancesOnly(t *testing.T) {
	root := t.TempDir()
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
		writeMIGFixture(t, root, path, contents)
	}
	got, err := getMIGCapabilities(root, []uint32{1, 2, 21, 22})
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
	} {
		t.Run(contents, func(t *testing.T) {
			root := t.TempDir()
			writeMIGFixture(t, root, "capabilities/gpu0/mig/gi0/access", contents)
			if _, err := getMIGCapabilities(root, []uint32{3}); err == nil {
				t.Fatal("accepted malformed capability metadata")
			}
		})
	}
}

func TestMIGCapabilitiesMissingTree(t *testing.T) {
	got, err := getMIGCapabilities(t.TempDir(), []uint32{3})
	if err != nil || len(got) != 0 {
		t.Errorf("capabilities = %v, %v; want empty map", got, err)
	}
}
