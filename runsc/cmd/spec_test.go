// Copyright 2025 The gVisor Authors.
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

package cmd

import (
	"os"
	"path"
	"path/filepath"
	"sort"
	"syscall"
	"testing"

	"github.com/google/go-cmp/cmp"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/protobuf/proto"
)

func makedev(maj, min uint32) uint64 {
	return (uint64(min) & 0xff) | (uint64(maj) & 0xfff << 8) | ((uint64(min) &^ 0xff) << 12) | ((uint64(maj) &^ 0xfff) << 32)
}

type testDeviceInfo struct {
	path  string
	major int64
	minor int64
}

func TestFindAllTPUs(t *testing.T) {
	testDeviceDir, err := os.MkdirTemp("", "spec-test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(testDeviceDir)

	devDir := path.Join(testDeviceDir, "dev")
	if err := os.Mkdir(devDir, 0777); err != nil {
		t.Fatalf("failed to create dev dir: %v", err)
	}
	vfioDir := path.Join(devDir, "vfio")
	if err := os.Mkdir(vfioDir, 0777); err != nil {
		t.Fatalf("failed to create vfio dir: %v", err)
	}

	devices := []testDeviceInfo{
		{path: "dev/vfio/0", major: 1, minor: 1},
		{path: "dev/vfio/1", major: 1, minor: 2},
		{path: "dev/accel0", major: 2, minor: 1},
		{path: "dev/accel1", major: 2, minor: 2},
	}
	for _, dev := range devices {
		devPath := path.Join(testDeviceDir, dev.path)
		rdev := makedev(uint32(dev.major), uint32(dev.minor))
		if err := syscall.Mknod(devPath, syscall.S_IFCHR|0666, int(rdev)); err != nil {
			t.Skipf("failed to mknod %q: %v. This test may require root privileges to run.", devPath, err)
		}
	}

	// Create a non-device file, should be ignored.
	nonDevicePath := path.Join(vfioDir, "not-a-device")
	if err := os.WriteFile(nonDevicePath, []byte{}, 0666); err != nil {
		t.Fatalf("failed to create non-device file: %v", err)
	}

	foundDevices := findAllTPUs(testDeviceDir)
	if len(foundDevices) != len(devices) {
		t.Errorf("findAllTPUs() got %d devices, want %d", len(foundDevices), len(devices))
	}

	// Sort devices by path to compare them.
	sort.Slice(foundDevices, func(i, j int) bool {
		return foundDevices[i].Path < foundDevices[j].Path
	})

	mode := os.FileMode(0666)
	var wantDevices []specs.LinuxDevice
	for _, dev := range devices {
		wantDevices = append(wantDevices, specs.LinuxDevice{
			Path:     filepath.Join(testDeviceDir, dev.path),
			Type:     "c",
			Major:    dev.major,
			Minor:    dev.minor,
			FileMode: &mode,
			UID:      proto.Uint32(0),
			GID:      proto.Uint32(0),
		})
	}
	sort.Slice(wantDevices, func(i, j int) bool {
		return wantDevices[i].Path < wantDevices[j].Path
	})

	if diff := cmp.Diff(wantDevices, foundDevices); diff != "" {
		t.Errorf("findAllTPUs() returned diff (-want +got):\n%s", diff)
	}
}
