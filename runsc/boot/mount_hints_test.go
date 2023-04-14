// Copyright 2022 The gVisor Authors.
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

package boot

import (
	"reflect"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

func TestPodMountHintsHappy(t *testing.T) {
	spec := &specs.Spec{
		Annotations: map[string]string{
			MountPrefix + "mount1.source": "foo",
			MountPrefix + "mount1.type":   "tmpfs",
			MountPrefix + "mount1.share":  "pod",

			MountPrefix + "mount2.source":  "bar",
			MountPrefix + "mount2.type":    "bind",
			MountPrefix + "mount2.share":   "container",
			MountPrefix + "mount2.options": "rw,private",
		},
	}
	podHints, err := newPodMountHints(spec)
	if err != nil {
		t.Fatalf("newPodMountHints failed: %v", err)
	}

	// Check that fields were set correctly.
	mount1 := podHints.mounts["mount1"]
	if want := "mount1"; want != mount1.name {
		t.Errorf("mount1 name, want: %q, got: %q", want, mount1.name)
	}
	if want := "foo"; want != mount1.mount.Source {
		t.Errorf("mount1 source, want: %q, got: %q", want, mount1.mount.Source)
	}
	if want := "tmpfs"; want != mount1.mount.Type {
		t.Errorf("mount1 type, want: %q, got: %q", want, mount1.mount.Type)
	}
	if want := pod; want != mount1.share {
		t.Errorf("mount1 type, want: %q, got: %q", want, mount1.share)
	}
	if want := []string(nil); !reflect.DeepEqual(want, mount1.mount.Options) {
		t.Errorf("mount1 type, want: %q, got: %q", want, mount1.mount.Options)
	}

	mount2 := podHints.mounts["mount2"]
	if want := "mount2"; want != mount2.name {
		t.Errorf("mount2 name, want: %q, got: %q", want, mount2.name)
	}
	if want := "bar"; want != mount2.mount.Source {
		t.Errorf("mount2 source, want: %q, got: %q", want, mount2.mount.Source)
	}
	if want := "bind"; want != mount2.mount.Type {
		t.Errorf("mount2 type, want: %q, got: %q", want, mount2.mount.Type)
	}
	if want := container; want != mount2.share {
		t.Errorf("mount2 type, want: %q, got: %q", want, mount2.share)
	}
	if want := []string{"rw", "private"}; !reflect.DeepEqual(want, mount2.mount.Options) {
		t.Errorf("mount2 type, want: %q, got: %q", want, mount2.mount.Options)
	}
}

func TestPodMountHintsErrors(t *testing.T) {
	for _, tst := range []struct {
		name        string
		annotations map[string]string
		error       string
	}{
		{
			name: "too short",
			annotations: map[string]string{
				MountPrefix + "mount1": "foo",
			},
			error: "invalid mount annotation",
		},
		{
			name: "no name",
			annotations: map[string]string{
				MountPrefix + ".source": "foo",
			},
			error: "invalid mount name",
		},
		{
			name: "missing source",
			annotations: map[string]string{
				MountPrefix + "mount1.type":  "tmpfs",
				MountPrefix + "mount1.share": "pod",
			},
			error: "source field",
		},
		{
			name: "missing type",
			annotations: map[string]string{
				MountPrefix + "mount1.source": "foo",
				MountPrefix + "mount1.share":  "pod",
			},
			error: "type field",
		},
		{
			name: "missing share",
			annotations: map[string]string{
				MountPrefix + "mount1.source": "foo",
				MountPrefix + "mount1.type":   "tmpfs",
			},
			error: "share field",
		},
		{
			name: "invalid source",
			annotations: map[string]string{
				MountPrefix + "mount1.source": "",
				MountPrefix + "mount1.type":   "tmpfs",
				MountPrefix + "mount1.share":  "pod",
			},
			error: "source field for \"mount1\" has not been set",
		},
		{
			name: "invalid type",
			annotations: map[string]string{
				MountPrefix + "mount1.source": "foo",
				MountPrefix + "mount1.type":   "invalid-type",
				MountPrefix + "mount1.share":  "pod",
			},
			error: "type field for \"mount1\" has not been set",
		},
		{
			name: "invalid share",
			annotations: map[string]string{
				MountPrefix + "mount1.source": "foo",
				MountPrefix + "mount1.type":   "tmpfs",
				MountPrefix + "mount1.share":  "invalid-share",
			},
			error: "share field for \"mount1\" has not been set",
		},
		{
			name: "duplicate source",
			annotations: map[string]string{
				MountPrefix + "mount1.source": "foo",
				MountPrefix + "mount1.type":   "tmpfs",
				MountPrefix + "mount1.share":  "pod",

				MountPrefix + "mount2.source": "foo",
				MountPrefix + "mount2.type":   "bind",
				MountPrefix + "mount2.share":  "container",
			},
			error: "have the same mount source",
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			spec := &specs.Spec{Annotations: tst.annotations}
			podHints, err := newPodMountHints(spec)
			if err == nil || !strings.Contains(err.Error(), tst.error) {
				t.Errorf("newPodMountHints invalid error, want: .*%s.*, got: %v", tst.error, err)
			}
			if podHints != nil {
				t.Errorf("newPodMountHints must return nil on failure: %+v", podHints)
			}
		})
	}
}

func TestHintsCheckCompatible(t *testing.T) {
	for _, tc := range []struct {
		name        string
		masterOpts  []string
		replicaOpts []string
		err         string
	}{
		{
			name: "empty",
		},
		{
			name:        "same",
			masterOpts:  []string{"ro", "noatime", "noexec"},
			replicaOpts: []string{"ro", "noatime", "noexec"},
		},
		{
			name:        "compatible",
			masterOpts:  []string{"rw", "atime", "exec"},
			replicaOpts: []string{"ro", "noatime", "noexec"},
		},
		{
			name:        "unsupported",
			masterOpts:  []string{"nofoo", "nodev"},
			replicaOpts: []string{"foo", "dev"},
		},
		{
			name:        "incompatible-ro",
			masterOpts:  []string{"ro"},
			replicaOpts: []string{"rw"},
			err:         "read-write",
		},
		{
			name:        "incompatible-atime",
			masterOpts:  []string{"noatime"},
			replicaOpts: []string{"atime"},
			err:         "noatime",
		},
		{
			name:        "incompatible-exec",
			masterOpts:  []string{"noexec"},
			replicaOpts: []string{"exec"},
			err:         "noexec",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			master := mountHint{mount: specs.Mount{Options: tc.masterOpts}}
			replica := specs.Mount{Options: tc.replicaOpts}
			if err := master.checkCompatible(&replica); err != nil {
				if !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("wrong error, want: %q, got: %q", tc.err, err)
				}
			} else {
				if len(tc.err) > 0 {
					t.Fatalf("error %q expected", tc.err)
				}
			}
		})
	}
}
