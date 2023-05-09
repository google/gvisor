// Copyright 2019 The gVisor Authors.
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

package utils

import (
	"fmt"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

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
		name         string
		spec         *specs.Spec
		expected     *specs.Spec
		expectErr    bool
		expectUpdate bool
	}{
		{
			name: "volume annotations for sandbox",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                       testLogDirPath,
					ContainerTypeAnnotation:                       containerTypeSandbox,
					volumeKeyPrefix + testVolumeName + ".share":   "pod",
					volumeKeyPrefix + testVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options": "ro",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                       testLogDirPath,
					ContainerTypeAnnotation:                       containerTypeSandbox,
					volumeKeyPrefix + testVolumeName + ".share":   "pod",
					volumeKeyPrefix + testVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options": "ro",
					volumeKeyPrefix + testVolumeName + ".source":  testVolumePath,
				},
			},
			expectUpdate: true,
		},
		{
			name: "volume annotations for sandbox with legacy log path",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                       testLegacyLogDirPath,
					ContainerTypeAnnotation:                       containerTypeSandbox,
					volumeKeyPrefix + testVolumeName + ".share":   "pod",
					volumeKeyPrefix + testVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options": "ro",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                       testLegacyLogDirPath,
					ContainerTypeAnnotation:                       containerTypeSandbox,
					volumeKeyPrefix + testVolumeName + ".share":   "pod",
					volumeKeyPrefix + testVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options": "ro",
					volumeKeyPrefix + testVolumeName + ".source":  testVolumePath,
				},
			},
			expectUpdate: true,
		},
		{
			name: "tmpfs: volume annotations for container",
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
					ContainerTypeAnnotation:                       ContainerTypeContainer,
					volumeKeyPrefix + testVolumeName + ".share":   "pod",
					volumeKeyPrefix + testVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options": "ro",
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
					ContainerTypeAnnotation:                       ContainerTypeContainer,
					volumeKeyPrefix + testVolumeName + ".share":   "pod",
					volumeKeyPrefix + testVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options": "ro",
				},
			},
			expectUpdate: true,
		},
		{
			name: "bind: volume annotations for container",
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
					ContainerTypeAnnotation:                       ContainerTypeContainer,
					volumeKeyPrefix + testVolumeName + ".share":   "container",
					volumeKeyPrefix + testVolumeName + ".type":    "bind",
					volumeKeyPrefix + testVolumeName + ".options": "ro",
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
					ContainerTypeAnnotation:                       ContainerTypeContainer,
					volumeKeyPrefix + testVolumeName + ".share":   "container",
					volumeKeyPrefix + testVolumeName + ".type":    "bind",
					volumeKeyPrefix + testVolumeName + ".options": "ro",
				},
			},
			expectUpdate: true,
		},
		{
			name: "should not return error without pod log directory",
			spec: &specs.Spec{
				Annotations: map[string]string{
					ContainerTypeAnnotation:                       containerTypeSandbox,
					volumeKeyPrefix + testVolumeName + ".share":   "pod",
					volumeKeyPrefix + testVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options": "ro",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					ContainerTypeAnnotation:                       containerTypeSandbox,
					volumeKeyPrefix + testVolumeName + ".share":   "pod",
					volumeKeyPrefix + testVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options": "ro",
				},
			},
		},
		{
			name: "should return error if volume path does not exist",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:              testLogDirPath,
					ContainerTypeAnnotation:              containerTypeSandbox,
					volumeKeyPrefix + "notexist.share":   "pod",
					volumeKeyPrefix + "notexist.type":    "tmpfs",
					volumeKeyPrefix + "notexist.options": "ro",
				},
			},
			expectErr: true,
		},
		{
			name: "no volume annotations for sandbox",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation: testLogDirPath,
					ContainerTypeAnnotation: containerTypeSandbox,
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation: testLogDirPath,
					ContainerTypeAnnotation: containerTypeSandbox,
				},
			},
		},
		{
			name: "no volume annotations for container",
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
					ContainerTypeAnnotation: ContainerTypeContainer,
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
					ContainerTypeAnnotation: ContainerTypeContainer,
				},
			},
		},
		{
			name: "bind options removed",
			spec: &specs.Spec{
				Annotations: map[string]string{
					ContainerTypeAnnotation:                       ContainerTypeContainer,
					volumeKeyPrefix + testVolumeName + ".share":   "pod",
					volumeKeyPrefix + testVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options": "ro",
					volumeKeyPrefix + testVolumeName + ".source":  testVolumePath,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/dst",
						Type:        "bind",
						Source:      testVolumePath,
						Options:     []string{"ro", "bind", "rbind"},
					},
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					ContainerTypeAnnotation:                       ContainerTypeContainer,
					volumeKeyPrefix + testVolumeName + ".share":   "pod",
					volumeKeyPrefix + testVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options": "ro",
					volumeKeyPrefix + testVolumeName + ".source":  testVolumePath,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/dst",
						Type:        "tmpfs",
						Source:      testVolumePath,
						Options:     []string{"ro"},
					},
				},
			},
			expectUpdate: true,
		},
		{
			name: "shm-sandbox",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation: testLogDirPath,
					ContainerTypeAnnotation: containerTypeSandbox,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/dev/shm",
						Type:        "bind",
						Source:      testVolumePath,
						Options:     []string{"ro", "foo"},
					},
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                   testLogDirPath,
					ContainerTypeAnnotation:                   containerTypeSandbox,
					volumeKeyPrefix + devshmName + ".share":   "pod",
					volumeKeyPrefix + devshmName + ".type":    "tmpfs",
					volumeKeyPrefix + devshmName + ".options": "rw",
					volumeKeyPrefix + devshmName + ".source":  testVolumePath,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/dev/shm",
						Type:        "tmpfs",
						Source:      testVolumePath,
						Options:     []string{"ro", "foo"},
					},
				},
			},
			expectUpdate: true,
		},
		{
			name: "shm-container",
			spec: &specs.Spec{
				Annotations: map[string]string{
					ContainerTypeAnnotation: ContainerTypeContainer,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/dev/shm",
						Type:        "bind",
						Source:      testVolumePath,
						Options:     []string{"ro", "foo"},
					},
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					ContainerTypeAnnotation: ContainerTypeContainer,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/dev/shm",
						Type:        "tmpfs",
						Source:      testVolumePath,
						Options:     []string{"ro", "foo"},
					},
				},
			},
			expectUpdate: true,
		},
		{
			name: "shm-duplicate",
			spec: &specs.Spec{
				Annotations: map[string]string{
					ContainerTypeAnnotation: ContainerTypeContainer,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/dev/shm",
						Type:        "bind",
						Source:      testVolumePath,
						Options:     []string{"ro", "foo"},
					},
					{
						Destination: "/dev/shm",
						Type:        "tmpfs",
					},
					{
						Destination: "/home",
						Type:        "bind",
						Source:      "/another/mount",
						Options:     []string{"rw"},
					},
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					ContainerTypeAnnotation: ContainerTypeContainer,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/dev/shm",
						Type:        "tmpfs",
						Source:      testVolumePath,
						Options:     []string{"ro", "foo"},
					},
					{
						Destination: "/home",
						Type:        "bind",
						Source:      "/another/mount",
						Options:     []string{"rw"},
					},
				},
			},
			expectUpdate: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			updated, err := UpdateVolumeAnnotations(test.spec)
			if test.expectErr {
				if err == nil {
					t.Fatal("UpdateVolumeAnnotations(spec): nil, want: error")
				}
				return
			}
			if err != nil {
				t.Fatalf("UpdateVolumeAnnotations(spec): %v", err)
			}
			if test.expectUpdate != updated {
				t.Errorf("want: %v, got: %v", test.expectUpdate, updated)
			}
			if !reflect.DeepEqual(test.expected, test.spec) {
				t.Fatalf("want: %+v, got: %+v", test.expected, test.spec)
			}
		})
	}
}
