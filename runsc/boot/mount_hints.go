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

type shareType int

const (
	invalid shareType = iota

	// container shareType indicates that the mount is used by a single container.
	container

	// pod shareType indicates that the mount is used by more than one container
	// inside the pod.
	pod

	// shared shareType indicates that the mount can also be shared with a process
	// outside the pod, e.g. NFS.
	shared
)

func parseShare(val string) (shareType, error) {
	switch val {
	case "container":
		return container, nil
	case "pod":
		return pod, nil
	case "shared":
		return shared, nil
	default:
		return 0, fmt.Errorf("invalid share value %q", val)
	}
}

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

// podMountHints contains a collection of mountHints for the pod.
type podMountHints struct {
	mounts map[string]*mountHint
}

func newPodMountHints(spec *specs.Spec) (*podMountHints, error) {
	mnts := make(map[string]*mountHint)
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
				mnt = &mountHint{name: name}
				mnts[name] = mnt
			}
			if err := mnt.setField(parts[1], v); err != nil {
				return nil, err
			}
		}
	}

	// Validate all hints after done parsing.
	for name, m := range mnts {
		log.Infof("Mount annotation found, name: %s, source: %q, type: %s, share: %v", name, m.mount.Source, m.mount.Type, m.share)
		if m.share == invalid {
			return nil, fmt.Errorf("share field for %q has not been set", m.name)
		}
		if len(m.mount.Source) == 0 {
			return nil, fmt.Errorf("source field for %q has not been set", m.name)
		}
		if len(m.mount.Type) == 0 {
			return nil, fmt.Errorf("type field for %q has not been set", m.name)
		}

		// Check for duplicate mount sources.
		for name2, m2 := range mnts {
			if name != name2 && m.mount.Source == m2.mount.Source {
				return nil, fmt.Errorf("mounts %q and %q have the same mount source %q", m.name, m2.name, m.mount.Source)
			}
		}
	}

	return &podMountHints{mounts: mnts}, nil
}

// mountHint represents extra information about mounts that are provided via
// annotations. They can override mount type, and provide sharing information
// so that mounts can be correctly shared inside the pod.
type mountHint struct {
	name  string
	share shareType
	mount specs.Mount

	// vfsMount is the master mount for the volume. For mounts with 'pod' share
	// the master volume is bind mounted inside the containers.
	vfsMount *vfs.Mount
}

func (m *mountHint) setField(key, val string) error {
	switch key {
	case "source":
		if len(val) == 0 {
			return fmt.Errorf("source cannot be empty")
		}
		m.mount.Source = val
	case "type":
		return m.setType(val)
	case "share":
		share, err := parseShare(val)
		if err != nil {
			return err
		}
		m.share = share
	case "options":
		return m.setOptions(val)
	default:
		return fmt.Errorf("invalid mount annotation: %s=%s", key, val)
	}
	return nil
}

func (m *mountHint) setType(val string) error {
	switch val {
	case "tmpfs", "bind":
		m.mount.Type = val
	default:
		return fmt.Errorf("invalid type %q", val)
	}
	return nil
}

func (m *mountHint) setOptions(val string) error {
	opts := strings.Split(val, ",")
	if err := specutils.ValidateMountOptions(opts); err != nil {
		return err
	}
	m.mount.Options = opts
	return nil
}

func (m *mountHint) isSupported() bool {
	return m.mount.Type == tmpfs.Name && m.share == pod
}

// checkCompatible verifies that shared mount is compatible with master.
// Master options must be the same or less restrictive than the container mount,
// e.g. master can be 'rw' while container mounts as 'ro'.
func (m *mountHint) checkCompatible(replica *specs.Mount) error {
	masterOpts := parseMountOptions(m.mount.Options)
	replicaOpts := parseMountOptions(replica.Options)

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

func (m *mountHint) fileAccessType() config.FileAccessType {
	if m.share == container {
		return config.FileAccessExclusive
	}
	return config.FileAccessShared
}

func (p *podMountHints) findMount(mount *specs.Mount) *mountHint {
	for _, m := range p.mounts {
		if m.mount.Source == mount.Source {
			return m
		}
	}
	return nil
}
