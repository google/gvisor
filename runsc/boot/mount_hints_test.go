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
	"slices"
	"strings"
	"testing"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/erofs"
	"gvisor.dev/gvisor/runsc/config"
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
	podHints, err := NewPodMountHints(spec)
	if err != nil {
		t.Fatalf("newPodMountHints failed: %v", err)
	}

	// Check that fields were set correctly.
	mount1 := podHints.Mounts["mount1"]
	if want := "mount1"; want != mount1.Name {
		t.Errorf("mount1 name, want: %q, got: %q", want, mount1.Name)
	}
	if want := "foo"; want != mount1.Mount.Source {
		t.Errorf("mount1 source, want: %q, got: %q", want, mount1.Mount.Source)
	}
	if want := "tmpfs"; want != mount1.Mount.Type {
		t.Errorf("mount1 type, want: %q, got: %q", want, mount1.Mount.Type)
	}
	if want := pod; want != mount1.Share {
		t.Errorf("mount1 type, want: %q, got: %q", want, mount1.Share)
	}
	if want := []string(nil); !slices.Equal(want, mount1.Mount.Options) {
		t.Errorf("mount1 type, want: %q, got: %q", want, mount1.Mount.Options)
	}

	mount2 := podHints.Mounts["mount2"]
	if want := "mount2"; want != mount2.Name {
		t.Errorf("mount2 name, want: %q, got: %q", want, mount2.Name)
	}
	if want := "bar"; want != mount2.Mount.Source {
		t.Errorf("mount2 source, want: %q, got: %q", want, mount2.Mount.Source)
	}
	if want := "bind"; want != mount2.Mount.Type {
		t.Errorf("mount2 type, want: %q, got: %q", want, mount2.Mount.Type)
	}
	if want := container; want != mount2.Share {
		t.Errorf("mount2 type, want: %q, got: %q", want, mount2.Share)
	}
	if want := []string{"rw", "private"}; !slices.Equal(want, mount2.Mount.Options) {
		t.Errorf("mount2 type, want: %q, got: %q", want, mount2.Mount.Options)
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
			podHints, err := NewPodMountHints(spec)
			if err == nil || !strings.Contains(err.Error(), tst.error) {
				t.Errorf("newPodMountHints invalid error, want: .*%s.*, got: %v", tst.error, err)
			}
			if podHints != nil {
				t.Errorf("newPodMountHints must return nil on failure: %+v", podHints)
			}
		})
	}
}

// Tests that when a required mount annotation is missing, the entire mount
// hint is omitted and ignored.
func TestPodMountHintsIgnore(t *testing.T) {
	for _, tst := range []struct {
		name        string
		annotations map[string]string
	}{
		{
			name: "invalid source",
			annotations: map[string]string{
				MountPrefix + "mount1.source": "",
				MountPrefix + "mount1.type":   "tmpfs",
				MountPrefix + "mount1.share":  "pod",
			},
		},
		{
			name: "invalid type",
			annotations: map[string]string{
				MountPrefix + "mount1.source": "foo",
				MountPrefix + "mount1.type":   "invalid",
				MountPrefix + "mount1.share":  "pod",
			},
		},
		{
			name: "invalid share",
			annotations: map[string]string{
				MountPrefix + "mount1.source": "foo",
				MountPrefix + "mount1.type":   "tmpfs",
				MountPrefix + "mount1.share":  "invalid",
			},
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			spec := &specs.Spec{Annotations: tst.annotations}
			podHints, err := NewPodMountHints(spec)
			if err != nil {
				t.Errorf("newPodMountHints() failed: %v", err)
			} else if podHints != nil {
				if hint, ok := podHints.Mounts["mount1"]; ok {
					t.Errorf("hint was provided when it should have been omitted: %+v", hint)
				}
			}
		})
	}
}

func TestIgnoreInvalidMountOptions(t *testing.T) {
	spec := &specs.Spec{
		Annotations: map[string]string{
			MountPrefix + "mount1.source":  "foo",
			MountPrefix + "mount1.type":    "tmpfs",
			MountPrefix + "mount1.share":   "container",
			MountPrefix + "mount1.options": "rw,shared,noexec",
		},
	}
	podHints, err := NewPodMountHints(spec)
	if err != nil {
		t.Fatalf("newPodMountHints failed: %v", err)
	}
	mount1 := podHints.Mounts["mount1"]
	if want := []string{"rw", "noexec"}; !slices.Equal(want, mount1.Mount.Options) {
		t.Errorf("mount2 type, want: %q, got: %q", want, mount1.Mount.Options)
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
			master := MountHint{Mount: specs.Mount{Options: tc.masterOpts}}
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

// TestRootfsHintHappy tests that valid rootfs annotations can be parsed correctly.
func TestRootfsHintHappy(t *testing.T) {
	const imagePath = "/tmp/rootfs.img"
	spec := &specs.Spec{
		Annotations: map[string]string{
			RootfsPrefix + "source":  imagePath,
			RootfsPrefix + "type":    erofs.Name,
			RootfsPrefix + "overlay": config.OverlayMediumMemory().String(),
		},
	}
	hint, err := NewRootfsHint(spec)
	if err != nil {
		t.Fatalf("NewRootfsHint failed: %v", err)
	}

	// Check that fields were set correctly.
	if hint.Mount.Source != imagePath {
		t.Errorf("rootfs source, want: %q, got: %q", imagePath, hint.Mount.Source)
	}
	if hint.Mount.Type != erofs.Name {
		t.Errorf("rootfs type, want: %q, got: %q", erofs.Name, hint.Mount.Type)
	}
	if hint.Overlay.MediumType() != config.MemoryOverlay {
		t.Errorf("rootfs overlay, want: %q, got: %q", config.MemoryOverlay, hint.Overlay)
	}
}

// TestRootfsHintErrors tests that proper errors will be returned when parsing
// invalid rootfs annotations.
func TestRootfsHintErrors(t *testing.T) {
	const imagePath = "/tmp/rootfs.img"
	for _, tst := range []struct {
		name        string
		annotations map[string]string
		error       string
	}{
		{
			name: "invalid source",
			annotations: map[string]string{
				RootfsPrefix + "source": "invalid",
				RootfsPrefix + "type":   erofs.Name,
			},
			error: "invalid rootfs annotation",
		},
		{
			name: "invalid type",
			annotations: map[string]string{
				RootfsPrefix + "source": imagePath,
				RootfsPrefix + "type":   "invalid",
			},
			error: "invalid rootfs annotation",
		},
		{
			name: "invalid overlay",
			annotations: map[string]string{
				RootfsPrefix + "source":  imagePath,
				RootfsPrefix + "type":    erofs.Name,
				RootfsPrefix + "overlay": "invalid",
			},
			error: "invalid rootfs annotation",
		},
		{
			name: "invalid key",
			annotations: map[string]string{
				RootfsPrefix + "invalid": "invalid",
				RootfsPrefix + "source":  imagePath,
				RootfsPrefix + "type":    erofs.Name,
				RootfsPrefix + "overlay": config.OverlayMediumMemory().String(),
			},
			error: "invalid rootfs annotation",
		},
		{
			name: "missing source",
			annotations: map[string]string{
				RootfsPrefix + "type":    erofs.Name,
				RootfsPrefix + "overlay": config.OverlayMediumMemory().String(),
			},
			error: "rootfs annotations missing required field",
		},
		{
			name: "missing type",
			annotations: map[string]string{
				RootfsPrefix + "source":  imagePath,
				RootfsPrefix + "overlay": config.OverlayMediumMemory().String(),
			},
			error: "rootfs annotations missing required field",
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			spec := &specs.Spec{Annotations: tst.annotations}
			hint, err := NewRootfsHint(spec)
			if err == nil || !strings.Contains(err.Error(), tst.error) {
				t.Errorf("NewRootfsHint invalid error, want: .*%s.*, got: %v", tst.error, err)
			}
			if hint != nil {
				t.Errorf("NewRootfsHint must return nil on failure: %+v", hint)
			}
		})
	}
}
