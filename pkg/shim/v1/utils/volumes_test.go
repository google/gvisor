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
	"os"
	"reflect"
	"testing"

	"github.com/mohae/deepcopy"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
)

func TestUpdateVolumeAnnotations(t *testing.T) {
	dir, err := os.MkdirTemp("", "test-update-volume-annotations")
	if err != nil {
		t.Fatalf("create tempdir: %v", err)
	}
	defer os.RemoveAll(dir)
	kubeletPodsDir = dir

	const (
		testPodUID                = "testuid"
		testVolumeName            = "testvolume"
		testNonEmptyVolumeName    = "nonemptyvolume"
		testMemVolumeName         = "memvolume"
		testNonEmptyMemVolumeName = "nonemptymemvolume"
		testLogDirPath            = "/var/log/pods/testns_testname_" + testPodUID
		testLegacyLogDirPath      = "/var/log/pods/" + testPodUID
	)
	testVolumePath := fmt.Sprintf("%s/%s/volumes/%s/%s", dir, testPodUID, emptyDirVolumesDir, testVolumeName)
	if err := os.MkdirAll(testVolumePath, 0755); err != nil {
		t.Fatalf("Create test volume: %v", err)
	}

	testNonEmptyVolumePath := fmt.Sprintf("%s/%s/volumes/%s/%s", dir, testPodUID, emptyDirVolumesDir, testNonEmptyVolumeName)
	if err := os.MkdirAll(testNonEmptyVolumePath, 0755); err != nil {
		t.Fatalf("Create test volume: %v", err)
	}
	if err := os.WriteFile(testNonEmptyVolumePath+"/file", []byte("hello"), 0644); err != nil {
		t.Fatalf("Create test volume: %v", err)
	}

	// Memory-backed EmptyDirs, on which the kubelet mounts a size-limited tmpfs.
	testMemVolumePath := fmt.Sprintf("%s/%s/volumes/%s/%s", dir, testPodUID, emptyDirVolumesDir, testMemVolumeName)
	if err := os.MkdirAll(testMemVolumePath, 0755); err != nil {
		t.Fatalf("Create test volume: %v", err)
	}
	testNonEmptyMemVolumePath := fmt.Sprintf("%s/%s/volumes/%s/%s", dir, testPodUID, emptyDirVolumesDir, testNonEmptyMemVolumeName)
	if err := os.MkdirAll(testNonEmptyMemVolumePath, 0755); err != nil {
		t.Fatalf("Create test volume: %v", err)
	}
	if err := os.WriteFile(testNonEmptyMemVolumePath+"/file", []byte("hello"), 0644); err != nil {
		t.Fatalf("Create test volume: %v", err)
	}

	// The pod's /dev/shm, on which containerd mounts a size-limited tmpfs.
	testShmPath := dir + "/shm"

	// Only the paths above are on a tmpfs, regardless of the filesystem of the
	// test's temporary directory.
	oldStatfs := statfs
	defer func() { statfs = oldStatfs }()
	statfs = fakeStatfs(map[string]uint64{
		testMemVolumePath:         256 << 20, // 256MiB
		testNonEmptyMemVolumePath: 256 << 20, // 256MiB
		testShmPath:               64 << 20,  // 64MiB
	})

	for _, test := range []struct {
		name      string
		spec      *specs.Spec
		expected  *specs.Spec // If nil, the spec is expected to be unchanged.
		expectErr bool
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
		},
		{
			name: "non-empty volume for sandbox",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                               testLogDirPath,
					ContainerTypeAnnotation:                               containerTypeSandbox,
					volumeKeyPrefix + testNonEmptyVolumeName + ".share":   "pod",
					volumeKeyPrefix + testNonEmptyVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testNonEmptyVolumeName + ".options": "ro",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                               testLogDirPath,
					ContainerTypeAnnotation:                               containerTypeSandbox,
					volumeKeyPrefix + testNonEmptyVolumeName + ".share":   "shared",
					volumeKeyPrefix + testNonEmptyVolumeName + ".type":    "bind",
					volumeKeyPrefix + testNonEmptyVolumeName + ".options": "ro",
					volumeKeyPrefix + testNonEmptyVolumeName + ".source":  testNonEmptyVolumePath,
				},
			},
		},
		{
			name: "non-empty volume for container",
			spec: &specs.Spec{
				Mounts: []specs.Mount{
					{
						Destination: "/test",
						Type:        "bind",
						Source:      testNonEmptyVolumePath,
						Options:     []string{"ro"},
					},
				},
				Annotations: map[string]string{
					ContainerTypeAnnotation:                               ContainerTypeContainer,
					volumeKeyPrefix + testNonEmptyVolumeName + ".share":   "pod",
					volumeKeyPrefix + testNonEmptyVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testNonEmptyVolumeName + ".options": "ro",
				},
			},
		},
		{
			name: "force-shared: volume annotations for sandbox",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                                                    testLogDirPath,
					ContainerTypeAnnotation:                                                    containerTypeSandbox,
					volumeKeyPrefix + testVolumeName + ".share":                                "pod",
					volumeKeyPrefix + testVolumeName + ".type":                                 "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options":                              "ro",
					emptyDirAnnotationPrefix + testVolumeName + "." + emptyDirForceSharedField: "true",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                                                    testLogDirPath,
					ContainerTypeAnnotation:                                                    containerTypeSandbox,
					volumeKeyPrefix + testVolumeName + ".share":                                "shared",
					volumeKeyPrefix + testVolumeName + ".type":                                 "bind",
					volumeKeyPrefix + testVolumeName + ".options":                              "ro",
					volumeKeyPrefix + testVolumeName + ".source":                               testVolumePath,
					emptyDirAnnotationPrefix + testVolumeName + "." + emptyDirForceSharedField: "true",
				},
			},
		},
		{
			name: "force-shared: volume annotations for container",
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
					ContainerTypeAnnotation:                                                    ContainerTypeContainer,
					volumeKeyPrefix + testVolumeName + ".share":                                "pod",
					volumeKeyPrefix + testVolumeName + ".type":                                 "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options":                              "ro",
					emptyDirAnnotationPrefix + testVolumeName + "." + emptyDirForceSharedField: "true",
				},
			},
			// The mount type is left as a bind mount, so the spec is unchanged.
		},
		{
			name: "force-shared with false value is a no-op",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                                                    testLogDirPath,
					ContainerTypeAnnotation:                                                    containerTypeSandbox,
					volumeKeyPrefix + testVolumeName + ".share":                                "pod",
					volumeKeyPrefix + testVolumeName + ".type":                                 "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options":                              "ro",
					emptyDirAnnotationPrefix + testVolumeName + "." + emptyDirForceSharedField: "false",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                                                    testLogDirPath,
					ContainerTypeAnnotation:                                                    containerTypeSandbox,
					volumeKeyPrefix + testVolumeName + ".share":                                "pod",
					volumeKeyPrefix + testVolumeName + ".type":                                 "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options":                              "ro",
					volumeKeyPrefix + testVolumeName + ".source":                               testVolumePath,
					emptyDirAnnotationPrefix + testVolumeName + "." + emptyDirForceSharedField: "false",
				},
			},
		},
		{
			name: "bind: volume annotations for sandbox",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                       testLogDirPath,
					ContainerTypeAnnotation:                       containerTypeSandbox,
					volumeKeyPrefix + testVolumeName + ".share":   "container",
					volumeKeyPrefix + testVolumeName + ".type":    "bind",
					volumeKeyPrefix + testVolumeName + ".options": "ro",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                       testLogDirPath,
					ContainerTypeAnnotation:                       containerTypeSandbox,
					volumeKeyPrefix + testVolumeName + ".share":   "container",
					volumeKeyPrefix + testVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testVolumeName + ".options": "ro",
					volumeKeyPrefix + testVolumeName + ".source":  testVolumePath,
				},
			},
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
		},
		{
			name: "memory-backed volume for sandbox gets host tmpfs size",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                          testLogDirPath,
					ContainerTypeAnnotation:                          containerTypeSandbox,
					volumeKeyPrefix + testMemVolumeName + ".share":   "container",
					volumeKeyPrefix + testMemVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testMemVolumeName + ".options": "rw,rprivate",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                          testLogDirPath,
					ContainerTypeAnnotation:                          containerTypeSandbox,
					volumeKeyPrefix + testMemVolumeName + ".share":   "container",
					volumeKeyPrefix + testMemVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testMemVolumeName + ".options": "rw,rprivate,size=268435456",
					volumeKeyPrefix + testMemVolumeName + ".source":  testMemVolumePath,
				},
			},
		},
		{
			name: "memory-backed volume for sandbox without options gets host tmpfs size",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                        testLogDirPath,
					ContainerTypeAnnotation:                        containerTypeSandbox,
					volumeKeyPrefix + testMemVolumeName + ".share": "pod",
					volumeKeyPrefix + testMemVolumeName + ".type":  "tmpfs",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                          testLogDirPath,
					ContainerTypeAnnotation:                          containerTypeSandbox,
					volumeKeyPrefix + testMemVolumeName + ".share":   "pod",
					volumeKeyPrefix + testMemVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testMemVolumeName + ".options": "size=268435456",
					volumeKeyPrefix + testMemVolumeName + ".source":  testMemVolumePath,
				},
			},
		},
		{
			name: "memory-backed volume for sandbox keeps explicit size",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                          testLogDirPath,
					ContainerTypeAnnotation:                          containerTypeSandbox,
					volumeKeyPrefix + testMemVolumeName + ".share":   "pod",
					volumeKeyPrefix + testMemVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testMemVolumeName + ".options": "rw,size=1m",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                          testLogDirPath,
					ContainerTypeAnnotation:                          containerTypeSandbox,
					volumeKeyPrefix + testMemVolumeName + ".share":   "pod",
					volumeKeyPrefix + testMemVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testMemVolumeName + ".options": "rw,size=1m",
					volumeKeyPrefix + testMemVolumeName + ".source":  testMemVolumePath,
				},
			},
		},
		{
			// Only volumes that the admission controller marked as memory-backed
			// (type=tmpfs) get a size.
			name: "disk-backed volume for sandbox does not get host tmpfs size",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                          testLogDirPath,
					ContainerTypeAnnotation:                          containerTypeSandbox,
					volumeKeyPrefix + testMemVolumeName + ".share":   "container",
					volumeKeyPrefix + testMemVolumeName + ".type":    "bind",
					volumeKeyPrefix + testMemVolumeName + ".options": "rw,rprivate",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                          testLogDirPath,
					ContainerTypeAnnotation:                          containerTypeSandbox,
					volumeKeyPrefix + testMemVolumeName + ".share":   "container",
					volumeKeyPrefix + testMemVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testMemVolumeName + ".options": "rw,rprivate",
					volumeKeyPrefix + testMemVolumeName + ".source":  testMemVolumePath,
				},
			},
		},
		{
			// Non-empty EmptyDirs are bind mounted from the host tmpfs, which
			// enforces its size limit itself.
			name: "non-empty memory-backed volume for sandbox does not get host tmpfs size",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                                  testLogDirPath,
					ContainerTypeAnnotation:                                  containerTypeSandbox,
					volumeKeyPrefix + testNonEmptyMemVolumeName + ".share":   "container",
					volumeKeyPrefix + testNonEmptyMemVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testNonEmptyMemVolumeName + ".options": "rw,rprivate",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                                  testLogDirPath,
					ContainerTypeAnnotation:                                  containerTypeSandbox,
					volumeKeyPrefix + testNonEmptyMemVolumeName + ".share":   "shared",
					volumeKeyPrefix + testNonEmptyMemVolumeName + ".type":    "bind",
					volumeKeyPrefix + testNonEmptyMemVolumeName + ".options": "rw,rprivate",
					volumeKeyPrefix + testNonEmptyMemVolumeName + ".source":  testNonEmptyMemVolumePath,
				},
			},
		},
		{
			// Same as above, for EmptyDirs forced to be bind mounted.
			name: "force-shared memory-backed volume for sandbox does not get host tmpfs size",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                                                       testLogDirPath,
					ContainerTypeAnnotation:                                                       containerTypeSandbox,
					volumeKeyPrefix + testMemVolumeName + ".share":                                "container",
					volumeKeyPrefix + testMemVolumeName + ".type":                                 "tmpfs",
					volumeKeyPrefix + testMemVolumeName + ".options":                              "rw,rprivate",
					emptyDirAnnotationPrefix + testMemVolumeName + "." + emptyDirForceSharedField: "true",
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                                                       testLogDirPath,
					ContainerTypeAnnotation:                                                       containerTypeSandbox,
					volumeKeyPrefix + testMemVolumeName + ".share":                                "shared",
					volumeKeyPrefix + testMemVolumeName + ".type":                                 "bind",
					volumeKeyPrefix + testMemVolumeName + ".options":                              "rw,rprivate",
					volumeKeyPrefix + testMemVolumeName + ".source":                               testMemVolumePath,
					emptyDirAnnotationPrefix + testMemVolumeName + "." + emptyDirForceSharedField: "true",
				},
			},
		},
		{
			// Mount annotations are only consumed from the sandbox spec, so
			// sub-container annotations are left unchanged.
			name: "memory-backed volume for container",
			spec: &specs.Spec{
				Mounts: []specs.Mount{
					{
						Destination: "/test",
						Type:        "bind",
						Source:      testMemVolumePath,
						Options:     []string{"rw"},
					},
				},
				Annotations: map[string]string{
					ContainerTypeAnnotation:                          ContainerTypeContainer,
					volumeKeyPrefix + testMemVolumeName + ".share":   "container",
					volumeKeyPrefix + testMemVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testMemVolumeName + ".options": "rw,rprivate",
				},
			},
			expected: &specs.Spec{
				Mounts: []specs.Mount{
					{
						Destination: "/test",
						Type:        "tmpfs",
						Source:      testMemVolumePath,
						Options:     []string{"rw"},
					},
				},
				Annotations: map[string]string{
					ContainerTypeAnnotation:                          ContainerTypeContainer,
					volumeKeyPrefix + testMemVolumeName + ".share":   "container",
					volumeKeyPrefix + testMemVolumeName + ".type":    "tmpfs",
					volumeKeyPrefix + testMemVolumeName + ".options": "rw,rprivate",
				},
			},
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
		},
		{
			// A spec without a container-type annotation is a sandbox, so the
			// map must be created before the /dev/shm hints are added.
			name: "shm-sandbox-nil-annotations",
			spec: &specs.Spec{
				Annotations: nil,
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
		},
		{
			name: "shm-sandbox-host-tmpfs",
			spec: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation: testLogDirPath,
					ContainerTypeAnnotation: containerTypeSandbox,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/dev/shm",
						Type:        "bind",
						Source:      testShmPath,
						Options:     []string{"rbind", "ro", "nosuid", "nodev", "noexec"},
					},
				},
			},
			expected: &specs.Spec{
				Annotations: map[string]string{
					sandboxLogDirAnnotation:                   testLogDirPath,
					ContainerTypeAnnotation:                   containerTypeSandbox,
					volumeKeyPrefix + devshmName + ".share":   "pod",
					volumeKeyPrefix + devshmName + ".type":    "tmpfs",
					volumeKeyPrefix + devshmName + ".options": "rw,size=67108864",
					volumeKeyPrefix + devshmName + ".source":  testShmPath,
				},
				Mounts: []specs.Mount{
					{
						Destination: "/dev/shm",
						Type:        "tmpfs",
						Source:      testShmPath,
						Options:     []string{"ro", "nosuid", "nodev", "noexec"},
					},
				},
			},
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
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			expectUpdate := test.expected != nil
			if test.expected == nil && !test.expectErr {
				test.expected = deepcopy.Copy(test.spec).(*specs.Spec)
			}
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
			if expectUpdate != updated {
				t.Errorf("want: %v, got: %v", expectUpdate, updated)
			}
			if !reflect.DeepEqual(test.expected, test.spec) {
				t.Fatalf("want: %+v, got: %+v", test.expected, test.spec)
			}
		})
	}
}

// fakeStatfs returns a statfs implementation that reports each path in
// tmpfsSizes as being on a tmpfs with the given size limit in bytes, and every
// other path as being on ext4.
func fakeStatfs(tmpfsSizes map[string]uint64) func(string, *unix.Statfs_t) error {
	return func(path string, st *unix.Statfs_t) error {
		const blockSize = 4096
		*st = unix.Statfs_t{
			Type:   unix.EXT4_SUPER_MAGIC,
			Bsize:  blockSize,
			Frsize: blockSize,
			Blocks: 1 << 20,
		}
		if size, ok := tmpfsSizes[path]; ok {
			st.Type = unix.TMPFS_MAGIC
			st.Blocks = size / blockSize
		}
		return nil
	}
}

func TestHostTmpfsSize(t *testing.T) {
	oldStatfs := statfs
	defer func() { statfs = oldStatfs }()

	for _, test := range []struct {
		name     string
		st       unix.Statfs_t
		err      error
		wantSize uint64
		wantOK   bool
	}{
		{
			name:     "tmpfs",
			st:       unix.Statfs_t{Type: unix.TMPFS_MAGIC, Bsize: 4096, Frsize: 4096, Blocks: 16384},
			wantSize: 64 << 20,
			wantOK:   true,
		},
		{
			name:     "tmpfs without frsize",
			st:       unix.Statfs_t{Type: unix.TMPFS_MAGIC, Bsize: 4096, Blocks: 16384},
			wantSize: 64 << 20,
			wantOK:   true,
		},
		{
			name: "tmpfs without size limit",
			st:   unix.Statfs_t{Type: unix.TMPFS_MAGIC, Bsize: 4096, Frsize: 4096},
		},
		{
			name: "not tmpfs",
			st:   unix.Statfs_t{Type: unix.EXT4_SUPER_MAGIC, Bsize: 4096, Frsize: 4096, Blocks: 16384},
		},
		{
			name: "statfs error",
			err:  unix.ENOENT,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			statfs = func(path string, st *unix.Statfs_t) error {
				*st = test.st
				return test.err
			}
			size, ok := hostTmpfsSize("/some/path")
			if size != test.wantSize || ok != test.wantOK {
				t.Errorf("hostTmpfsSize() = (%d, %t), want (%d, %t)", size, ok, test.wantSize, test.wantOK)
			}
		})
	}
}

func TestWithSizeOption(t *testing.T) {
	for _, test := range []struct {
		opts string
		want string
	}{
		{opts: "", want: "size=1024"},
		{opts: "rw", want: "rw,size=1024"},
		{opts: "rw,rprivate", want: "rw,rprivate,size=1024"},
		{opts: "rw,size=1m", want: "rw,size=1m"},
		{opts: "size=0,ro", want: "size=0,ro"},
	} {
		if got := withSizeOption(test.opts, 1024); got != test.want {
			t.Errorf("withSizeOption(%q, 1024) = %q, want %q", test.opts, got, test.want)
		}
	}
}
