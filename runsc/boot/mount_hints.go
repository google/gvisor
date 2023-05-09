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
	"fmt"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

// MountPrefix is the annotation prefix for mount hints.
const MountPrefix = "dev.gvisor.spec.mount."

// shareType indicates who can access/mutate the volume contents.
type shareType int

const (
	invalid shareType = iota

	// container shareType indicates that the mount is used by a single
	// container. There are no external observers.
	container

	// pod shareType indicates that the mount is used by more than one container
	// inside the pod. There are no external observers.
	pod

	// shared shareType indicates that the mount can also be shared with a process
	// outside the pod, e.g. NFS.
	shared
)

func (s shareType) String() string {
	switch s {
	case invalid:
		return "invalid"
	case container:
		return "container"
	case pod:
		return "pod"
	case shared:
		return "shared"
	default:
		return fmt.Sprintf("invalid share value %d", s)
	}
}

// lifecycleType indicates whether creation/deletion of the volume is tied to
// the pod or container's lifecycle.
type lifecycleType int

const (
	// sharedLife indicates that the volume's lifecycle is not tied to the pod.
	// The volume persists beyond the pod's life. This is the safe default.
	sharedLife lifecycleType = iota

	// podLife indicates that the volume's lifecycle is tied to the pod's
	// lifecycle. The volume is destroyed with the pod.
	podLife

	// containerLife indicates that the volume's lifecycle is tied to the
	// container's lifecycle. The volume is destroyed with the container.
	containerLife
)

func (o lifecycleType) String() string {
	switch o {
	case sharedLife:
		return "shared"
	case podLife:
		return "pod"
	case containerLife:
		return "container"
	default:
		return fmt.Sprintf("invalid lifecycle value %d", o)
	}
}

// PodMountHints contains a collection of mountHints for the pod.
type PodMountHints struct {
	mounts map[string]*MountHint
}

// NewPodMountHints instantiates PodMountHints using spec.
func NewPodMountHints(spec *specs.Spec) (*PodMountHints, error) {
	mnts := make(map[string]*MountHint)
	for k, v := range spec.Annotations {
		// Look for 'dev.gvisor.spec.mount' annotations and parse them.
		if strings.HasPrefix(k, MountPrefix) {
			// Remove the prefix and split the rest.
			parts := strings.Split(k[len(MountPrefix):], ".")
			if len(parts) != 2 {
				return nil, fmt.Errorf("invalid mount annotation: %s=%s", k, v)
			}
			name := parts[0]
			if len(name) == 0 {
				return nil, fmt.Errorf("invalid mount name: %s", name)
			}
			mnt := mnts[name]
			if mnt == nil {
				mnt = &MountHint{name: name}
				mnts[name] = mnt
			}
			if err := mnt.setField(parts[1], v); err != nil {
				log.Warningf("ignoring invalid mount annotation (name = %q, key = %q, value = %q): %v", name, parts[1], v, err)
			}
		}
	}

	// Validate all the parsed hints.
	for name, m := range mnts {
		log.Infof("Mount annotation found, name: %s, source: %q, type: %s, share: %v", name, m.mount.Source, m.mount.Type, m.share)
		if m.share == invalid || len(m.mount.Source) == 0 || len(m.mount.Type) == 0 {
			log.Warningf("ignoring mount annotations for %q because of missing required field(s)", name)
			delete(mnts, name)
			continue
		}

		// Check for duplicate mount sources.
		for name2, m2 := range mnts {
			if name != name2 && m.mount.Source == m2.mount.Source {
				return nil, fmt.Errorf("mounts %q and %q have the same mount source %q", m.name, m2.name, m.mount.Source)
			}
		}
	}

	return &PodMountHints{mounts: mnts}, nil
}

// MountHint represents extra information about mounts that are provided via
// annotations. They can override mount type, and provide sharing information
// so that mounts can be correctly shared inside the pod.
type MountHint struct {
	name      string
	share     shareType
	mount     specs.Mount
	lifecycle lifecycleType

	// vfsMount is the master mount for the volume. For mounts with 'pod' share
	// the master volume is bind mounted inside the containers.
	vfsMount *vfs.Mount
}

func (m *MountHint) setField(key, val string) error {
	switch key {
	case "source":
		if len(val) == 0 {
			return fmt.Errorf("source cannot be empty")
		}
		m.mount.Source = val
	case "type":
		return m.setType(val)
	case "share":
		return m.setShare(val)
	case "options":
		m.mount.Options = specutils.FilterMountOptions(strings.Split(val, ","))
	case "lifecycle":
		return m.setLifecycle(val)
	default:
		return fmt.Errorf("invalid mount annotation: %s=%s", key, val)
	}
	return nil
}

func (m *MountHint) setType(val string) error {
	switch val {
	case tmpfs.Name, Bind:
		m.mount.Type = val
	default:
		return fmt.Errorf("invalid type %q", val)
	}
	return nil
}

func (m *MountHint) setShare(val string) error {
	switch val {
	case container.String():
		m.share = container
	case pod.String():
		m.share = pod
	case shared.String():
		m.share = shared
	default:
		return fmt.Errorf("invalid share value %q", val)
	}
	return nil
}

func (m *MountHint) setLifecycle(val string) error {
	switch val {
	case containerLife.String():
		m.lifecycle = containerLife
	case podLife.String():
		m.lifecycle = podLife
	case sharedLife.String():
		m.lifecycle = sharedLife
	default:
		return fmt.Errorf("invalid lifecycle %q", val)
	}
	return nil
}

// shouldShareMount returns true if this mount should be configured as a shared
// mount that is shared among multiple containers in a pod.
func (m *MountHint) shouldShareMount() bool {
	// TODO(b/142076984): Only support tmpfs for now. Bind mounts require a
	// common gofer to mount all shared volumes.
	return m.mount.Type == tmpfs.Name && m.share == pod
}

// ShouldOverlay returns true if this mount should be overlaid.
func (m *MountHint) ShouldOverlay() bool {
	// TODO(b/142076984): Only support share=container for now. Once shared gofer
	// support is added, we can overlay shared bind mounts too.
	return m.mount.Type == Bind && m.share == container && m.lifecycle != sharedLife
}

// checkCompatible verifies that shared mount is compatible with master.
// Master options must be the same or less restrictive than the container mount,
// e.g. master can be 'rw' while container mounts as 'ro'.
func (m *MountHint) checkCompatible(replica *specs.Mount) error {
	masterOpts := ParseMountOptions(m.mount.Options)
	replicaOpts := ParseMountOptions(replica.Options)

	if masterOpts.ReadOnly && !replicaOpts.ReadOnly {
		return fmt.Errorf("cannot mount read-write shared mount because master is read-only, mount: %+v", replica)
	}
	if masterOpts.Flags.NoExec && !replicaOpts.Flags.NoExec {
		return fmt.Errorf("cannot mount exec enabled shared mount because master is noexec, mount: %+v", replica)
	}
	if masterOpts.Flags.NoATime && !replicaOpts.Flags.NoATime {
		return fmt.Errorf("cannot mount atime enabled shared mount because master is noatime, mount: %+v", replica)
	}
	return nil
}

// Precondition: m.mount.Type == Bind.
func (m *MountHint) fileAccessType() config.FileAccessType {
	if m.share == shared {
		return config.FileAccessShared
	}
	if m.shouldShareMount() {
		return config.FileAccessExclusive
	}
	if m.share == container {
		return config.FileAccessExclusive
	}
	return config.FileAccessShared
}

// FindMount finds the MountHint that applies to this mount.
func (p *PodMountHints) FindMount(mount *specs.Mount) *MountHint {
	for _, m := range p.mounts {
		if m.mount.Source == mount.Source {
			return m
		}
	}
	return nil
}
