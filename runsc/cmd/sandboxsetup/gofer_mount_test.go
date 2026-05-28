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

package sandboxsetup

import (
	"reflect"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestShouldExposeNvidiaDevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "nvidiactl", path: "/dev/nvidiactl", want: true},
		{name: "nvidia-uvm", path: "/dev/nvidia-uvm", want: true},
		{name: "nvidia0", path: "/dev/nvidia0", want: true},
		{name: "nvidia1", path: "/dev/nvidia1", want: true},
		{name: "nvidia42", path: "/dev/nvidia42", want: true},
		{name: "nvidia-uvm-tools", path: "/dev/nvidia-uvm-tools", want: false},
		{name: "nvidia-modeset", path: "/dev/nvidia-modeset", want: false},
		{name: "not nvidia", path: "/dev/sda", want: false},
		{name: "nvidia prefix but not device", path: "/dev/nvidia-cap1", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeNvidiaDevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeNvidiaDevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

func TestShouldExposeVFIODevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "vfio dir", path: "/dev/vfio/vfio", want: true},
		{name: "vfio group", path: "/dev/vfio/0", want: true},
		{name: "vfio dir itself", path: "/dev/vfio", want: true},
		{name: "not vfio", path: "/dev/sda", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeVFIODevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeVFIODevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}

func TestIsNvidiaDisableDeviceNodeModificationHook(t *testing.T) {
	tests := []struct {
		name string
		hook specs.Hook
		want bool
	}{
		{
			name: "match: absolute nvidia-ctk path",
			hook: specs.Hook{Path: "/usr/bin/nvidia-ctk", Args: []string{"nvidia-ctk", "hook", "disable-device-node-modification"}},
			want: true,
		},
		{
			name: "match: bare nvidia-ctk path",
			hook: specs.Hook{Path: "nvidia-ctk", Args: []string{"nvidia-ctk", "hook", "disable-device-node-modification"}},
			want: true,
		},
		{
			name: "match: extra args after subcommand",
			hook: specs.Hook{Path: "/usr/bin/nvidia-ctk", Args: []string{"nvidia-ctk", "hook", "disable-device-node-modification", "--container-spec", "/some/path"}},
			want: true,
		},
		{
			name: "no match: different subcommand",
			hook: specs.Hook{Path: "/usr/bin/nvidia-ctk", Args: []string{"nvidia-ctk", "hook", "create-symlinks"}},
			want: false,
		},
		{
			name: "no match: enable-cuda-compat",
			hook: specs.Hook{Path: "/usr/bin/nvidia-ctk", Args: []string{"nvidia-ctk", "hook", "enable-cuda-compat"}},
			want: false,
		},
		{
			name: "no match: not nvidia-ctk",
			hook: specs.Hook{Path: "/usr/bin/some-other-hook", Args: []string{"some-other-hook", "hook", "disable-device-node-modification"}},
			want: false,
		},
		{
			name: "no match: args too short",
			hook: specs.Hook{Path: "/usr/bin/nvidia-ctk", Args: []string{"nvidia-ctk", "hook"}},
			want: false,
		},
		{
			name: "no match: no args",
			hook: specs.Hook{Path: "/usr/bin/nvidia-ctk"},
			want: false,
		},
		{
			name: "no match: middle arg is not 'hook'",
			hook: specs.Hook{Path: "/usr/bin/nvidia-ctk", Args: []string{"nvidia-ctk", "cdi", "disable-device-node-modification"}},
			want: false,
		},
		{
			// Locks the suffix semantics: nvidia-ctk-foo does not end in
			// "nvidia-ctk", so it is not matched.
			name: "no match: path with nvidia-ctk prefix but extra suffix",
			hook: specs.Hook{Path: "/usr/bin/nvidia-ctk-foo", Args: []string{"nvidia-ctk-foo", "hook", "disable-device-node-modification"}},
			want: false,
		},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := isNvidiaDisableDeviceNodeModificationHook(tst.hook)
			if got != tst.want {
				t.Errorf("isNvidiaDisableDeviceNodeModificationHook(%+v) = %v, want %v", tst.hook, got, tst.want)
			}
		})
	}
}

func TestFilterNVProxyNoOpHooks(t *testing.T) {
	create := specs.Hook{Path: "/usr/bin/nvidia-ctk", Args: []string{"nvidia-ctk", "hook", "create-symlinks", "--link", "libcuda.so.1::/usr/lib/x86_64-linux-gnu/libcuda.so"}}
	cuda := specs.Hook{Path: "/usr/bin/nvidia-ctk", Args: []string{"nvidia-ctk", "hook", "enable-cuda-compat", "--host-driver-version=580.159.04"}}
	ldcache := specs.Hook{Path: "/usr/bin/nvidia-ctk", Args: []string{"nvidia-ctk", "hook", "update-ldcache", "--folder", "/usr/lib/x86_64-linux-gnu"}}
	disable := specs.Hook{Path: "/usr/bin/nvidia-ctk", Args: []string{"nvidia-ctk", "hook", "disable-device-node-modification"}}
	other := specs.Hook{Path: "/usr/bin/some-other-hook", Args: []string{"some-other-hook"}}

	tests := []struct {
		name  string
		hooks []specs.Hook
		want  []specs.Hook
	}{
		{name: "nil", hooks: nil, want: []specs.Hook{}},
		{name: "empty", hooks: []specs.Hook{}, want: []specs.Hook{}},
		{name: "only the no-op hook", hooks: []specs.Hook{disable}, want: []specs.Hook{}},
		{name: "no no-op hook", hooks: []specs.Hook{create, cuda, ldcache}, want: []specs.Hook{create, cuda, ldcache}},
		{name: "four NVIDIA hooks, no-op last", hooks: []specs.Hook{create, cuda, ldcache, disable}, want: []specs.Hook{create, cuda, ldcache}},
		{name: "four NVIDIA hooks, no-op first", hooks: []specs.Hook{disable, create, cuda, ldcache}, want: []specs.Hook{create, cuda, ldcache}},
		{name: "no-op interleaved with non-nvidia", hooks: []specs.Hook{other, disable, create}, want: []specs.Hook{other, create}},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := filterNVProxyNoOpHooks(tst.hooks)
			if !reflect.DeepEqual(got, tst.want) {
				t.Errorf("filterNVProxyNoOpHooks(%v) = %v, want %v", tst.hooks, got, tst.want)
			}
		})
	}
}

func TestShouldExposeTpuDevice(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		// VFIO devices are always detected as TPU devices regardless of sysfs.
		{name: "vfio device", path: "/dev/vfio/0", want: true},
		{name: "vfio vfio", path: "/dev/vfio/vfio", want: true},
		{name: "not tpu", path: "/dev/sda", want: false},
		{name: "empty", path: "", want: false},
	}
	for _, tst := range tests {
		t.Run(tst.name, func(t *testing.T) {
			got := ShouldExposeTpuDevice(tst.path)
			if got != tst.want {
				t.Errorf("ShouldExposeTpuDevice(%q) = %v, want %v", tst.path, got, tst.want)
			}
		})
	}
}
