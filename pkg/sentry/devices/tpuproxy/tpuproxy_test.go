// Copyright 2024 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tpuproxy

import (
	"path/filepath"
	"regexp"
	"slices"
	"testing"
)

func TestTPUPath(t *testing.T) {
	for _, tst := range []struct {
		name     string
		pathGlob string
		path     string
		submatch []string
	}{
		{
			name:     "TPUv4PCIPathMatch",
			pathGlob: pciPathGlobTPUv4,
			path:     "/sys/devices/pci0000:00/0000:00:01.0/accel/accel16",
			submatch: []string{"/sys/devices/pci0000:00/0000:00:01.0/accel/accel16", "16"},
		},
		{
			name:     "TPUv4PCIPathNoMatch",
			pathGlob: pciPathGlobTPUv4,
			path:     "/sys/devices/pci0000:00/0000:00:01.0/accel/123",
			submatch: nil,
		},
		{
			name:     "TPUv5PCIPathMatch",
			pathGlob: pciPathGlobTPUv5,
			path:     "/sys/devices/pci0000:00/0000:00:05.0/vfio-dev/vfio20",
			submatch: []string{"/sys/devices/pci0000:00/0000:00:05.0/vfio-dev/vfio20", "20"},
		},
		{
			name:     "TPUv5PCIPathNoMatch",
			pathGlob: pciPathGlobTPUv5,
			path:     "/sys/devices/pci0000:00/0000:00:05.0/vfio/vfio20",
			submatch: nil,
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			if _, err := filepath.Glob(tst.pathGlob); err != nil {
				t.Errorf("Malformed path glob: %v", err)
			}
			pathRegex := regexp.MustCompile(pathGlobToPathRegex[tst.pathGlob])
			if submatch := pathRegex.FindStringSubmatch(tst.path); !slices.Equal(submatch, tst.submatch) {
				t.Errorf("Match TPU PCI path, got: %v, want: %v", submatch, tst.submatch)
			}
		})
	}
}
