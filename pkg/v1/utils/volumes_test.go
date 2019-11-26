/*
Copyright 2019 Google LLC.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/containerd/cri/pkg/annotations"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestUpdateVolumeAnnotations(t *testing.T) {
	dir, err := ioutil.TempDir("", "test-update-volume-annotations")
	if err != nil {
		t.Fatalf("create tempdir: %v", err)
	}
	defer os.RemoveAll(dir)
	kubeletPodsDir = dir

	const (
		testPodUID           = "testuid"
		testVolumeName       = "testvolume"
		testLogDirPath       = "/var/log/pods/testns_testname_" + testPodUID
		testLegacyLogDirPath = "/var/log/pods/" + testPodUID
	)
	testVolumePath := fmt.Sprintf("%s/%s/volumes/kubernetes.io~empty-dir/%s", dir, testPodUID, testVolumeName)

	if err := os.MkdirAll(testVolumePath, 0755); err != nil {
		t.Fatalf("Create test volume: %v", err)
	}

	for _, test := range []struct {
		desc         string
		spec         *specs.Spec
		expected     *specs.Spec
		expectErr    bool
		expectUpdate bool
	}{
		{
			desc: "volume annotations for sandbox",
			spec: &specs.Spec{
				Annotations: map[string]string{
					annotations.SandboxLogDir:                              testLogDirPath,
					annotations.ContainerType:                              annotations.ContainerTypeSandbox,
					"gvisor.dev/spec/mount/" + testVolumeName + "/share":   "pod",
					"gvisor.dev/spec/mount/" + testVolumeName + "/type":    "tmpfs",
					"gvisor.dev/spec/mount/" + testVolumeName + "/options": "ro",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					annotations.SandboxLogDir:                              testLogDirPath,
					annotations.ContainerType:                              annotations.ContainerTypeSandbox,
					"gvisor.dev/spec/mount/" + testVolumeName + "/share":   "pod",
					"gvisor.dev/spec/mount/" + testVolumeName + "/type":    "tmpfs",
					"gvisor.dev/spec/mount/" + testVolumeName + "/options": "ro",
					"gvisor.dev/spec/mount/" + testVolumeName + "/source":  testVolumePath,
				},
			},
			expectUpdate: true,
		},
		{
			desc: "volume annotations for sandbox with legacy log path",
			spec: &specs.Spec{
				Annotations: map[string]string{
					annotations.SandboxLogDir:                              testLegacyLogDirPath,
					annotations.ContainerType:                              annotations.ContainerTypeSandbox,
					"gvisor.dev/spec/mount/" + testVolumeName + "/share":   "pod",
					"gvisor.dev/spec/mount/" + testVolumeName + "/type":    "tmpfs",
					"gvisor.dev/spec/mount/" + testVolumeName + "/options": "ro",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					annotations.SandboxLogDir:                              testLegacyLogDirPath,
					annotations.ContainerType:                              annotations.ContainerTypeSandbox,
					"gvisor.dev/spec/mount/" + testVolumeName + "/share":   "pod",
					"gvisor.dev/spec/mount/" + testVolumeName + "/type":    "tmpfs",
					"gvisor.dev/spec/mount/" + testVolumeName + "/options": "ro",
					"gvisor.dev/spec/mount/" + testVolumeName + "/source":  testVolumePath,
				},
			},
			expectUpdate: true,
		},
		{
			desc: "tmpfs: volume annotations for container",
			spec: &specs.Spec{
				Mounts: []specs.Mount{
					{
						Destination: "/test",
						Type:        "bind",
						Source:      testVolumePath,
						Options:     []string{"ro"},
					},
					{
						Destination: "/random",
						Type:        "bind",
						Source:      "/random",
						Options:     []string{"ro"},
					},
				},
				Annotations: map[string]string{
					annotations.ContainerType:                              annotations.ContainerTypeContainer,
					"gvisor.dev/spec/mount/" + testVolumeName + "/share":   "pod",
					"gvisor.dev/spec/mount/" + testVolumeName + "/type":    "tmpfs",
					"gvisor.dev/spec/mount/" + testVolumeName + "/options": "ro",
				},
			},
			expected: &specs.Spec{
				Mounts: []specs.Mount{
					{
						Destination: "/test",
						Type:        "tmpfs",
						Source:      testVolumePath,
						Options:     []string{"ro"},
					},
					{
						Destination: "/random",
						Type:        "bind",
						Source:      "/random",
						Options:     []string{"ro"},
					},
				},
				Annotations: map[string]string{
					annotations.ContainerType:                              annotations.ContainerTypeContainer,
					"gvisor.dev/spec/mount/" + testVolumeName + "/share":   "pod",
					"gvisor.dev/spec/mount/" + testVolumeName + "/type":    "tmpfs",
					"gvisor.dev/spec/mount/" + testVolumeName + "/options": "ro",
				},
			},
			expectUpdate: true,
		},
		{
			desc: "bind: volume annotations for container",
			spec: &specs.Spec{
				Mounts: []specs.Mount{
					{
						Destination: "/test",
						Type:        "bind",
						Source:      testVolumePath,
						Options:     []string{"ro"},
					},
				},
				Annotations: map[string]string{
					annotations.ContainerType:                              annotations.ContainerTypeContainer,
					"gvisor.dev/spec/mount/" + testVolumeName + "/share":   "container",
					"gvisor.dev/spec/mount/" + testVolumeName + "/type":    "bind",
					"gvisor.dev/spec/mount/" + testVolumeName + "/options": "ro",
				},
			},
			expected: &specs.Spec{
				Mounts: []specs.Mount{
					{
						Destination: "/test",
						Type:        "bind",
						Source:      testVolumePath,
						Options:     []string{"ro"},
					},
				},
				Annotations: map[string]string{
					annotations.ContainerType:                              annotations.ContainerTypeContainer,
					"gvisor.dev/spec/mount/" + testVolumeName + "/share":   "container",
					"gvisor.dev/spec/mount/" + testVolumeName + "/type":    "bind",
					"gvisor.dev/spec/mount/" + testVolumeName + "/options": "ro",
				},
			},
			expectUpdate: true,
		},
		{
			desc: "should not return error without pod log directory",
			spec: &specs.Spec{
				Annotations: map[string]string{
					annotations.ContainerType:                              annotations.ContainerTypeSandbox,
					"gvisor.dev/spec/mount/" + testVolumeName + "/share":   "pod",
					"gvisor.dev/spec/mount/" + testVolumeName + "/type":    "tmpfs",
					"gvisor.dev/spec/mount/" + testVolumeName + "/options": "ro",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					annotations.ContainerType:                              annotations.ContainerTypeSandbox,
					"gvisor.dev/spec/mount/" + testVolumeName + "/share":   "pod",
					"gvisor.dev/spec/mount/" + testVolumeName + "/type":    "tmpfs",
					"gvisor.dev/spec/mount/" + testVolumeName + "/options": "ro",
				},
			},
		},
		{
			desc: "should return error if volume path does not exist",
			spec: &specs.Spec{
				Annotations: map[string]string{
					annotations.SandboxLogDir:                testLogDirPath,
					annotations.ContainerType:                annotations.ContainerTypeSandbox,
					"gvisor.dev/spec/mount/notexist/share":   "pod",
					"gvisor.dev/spec/mount/notexist/type":    "tmpfs",
					"gvisor.dev/spec/mount/notexist/options": "ro",
				},
			},
			expectErr: true,
		},
		{
			desc: "no volume annotations for sandbox",
			spec: &specs.Spec{
				Annotations: map[string]string{
					annotations.SandboxLogDir: testLogDirPath,
					annotations.ContainerType: annotations.ContainerTypeSandbox,
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					annotations.SandboxLogDir: testLogDirPath,
					annotations.ContainerType: annotations.ContainerTypeSandbox,
				},
			},
		},
		{
			desc: "no volume annotations for container",
			spec: &specs.Spec{
				Mounts: []specs.Mount{
					{
						Destination: "/test",
						Type:        "bind",
						Source:      "/test",
						Options:     []string{"ro"},
					},
					{
						Destination: "/random",
						Type:        "bind",
						Source:      "/random",
						Options:     []string{"ro"},
					},
				},
				Annotations: map[string]string{
					annotations.ContainerType: annotations.ContainerTypeContainer,
				},
			},
			expected: &specs.Spec{
				Mounts: []specs.Mount{
					{
						Destination: "/test",
						Type:        "bind",
						Source:      "/test",
						Options:     []string{"ro"},
					},
					{
						Destination: "/random",
						Type:        "bind",
						Source:      "/random",
						Options:     []string{"ro"},
					},
				},
				Annotations: map[string]string{
					annotations.ContainerType: annotations.ContainerTypeContainer,
				},
			},
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			bundle, err := ioutil.TempDir(dir, "test-bundle")
			if err != nil {
				t.Fatalf("Create test bundle: %v", err)
			}
			err = UpdateVolumeAnnotations(bundle, test.spec)
			if test.expectErr {
				if err == nil {
					t.Fatal("Expected error, but got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			if !reflect.DeepEqual(test.expected, test.spec) {
				t.Fatalf("Expected %+v, got %+v", test.expected, test.spec)
			}
			if test.expectUpdate {
				b, err := ioutil.ReadFile(filepath.Join(bundle, "config.json"))
				if err != nil {
					t.Fatalf("Read spec from bundle: %v", err)
				}
				var spec specs.Spec
				if err := json.Unmarshal(b, &spec); err != nil {
					t.Fatalf("Unmarshal spec: %v", err)
				}
				if !reflect.DeepEqual(test.expected, &spec) {
					t.Fatalf("Expected %+v, got %+v", test.expected, &spec)
				}
			}
		})
	}
}
