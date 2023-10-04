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
	"path/filepath"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/erofs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"
)

const (
	// MountPrefix is the annotation prefix for mount hints applied at the pod level.
	MountPrefix = "dev.gvisor.spec.mount."

	// RootfsPrefix is the annotation prefix for rootfs hint applied at the container level.
	RootfsPrefix = "dev.gvisor.spec.rootfs."
)

// ShareType indicates who can access/mutate the volume contents.
type ShareType int

const (
	invalid ShareType = iota

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

func (s ShareType) String() string {
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

// PodMountHints contains a collection of mountHints for the pod.
type PodMountHints struct {
	Mounts map[string]*MountHint `json:"mounts"`
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
				mnt = &MountHint{Name: name}
				mnts[name] = mnt
			}
			if err := mnt.setField(parts[1], v); err != nil {
				log.Warningf("ignoring invalid mount annotation (name = %q, key = %q, value = %q): %v", name, parts[1], v, err)
			}
		}
	}

	// Validate all the parsed hints.
	for name, m := range mnts {
		log.Infof("Mount annotation found, name: %s, source: %q, type: %s, share: %v", name, m.Mount.Source, m.Mount.Type, m.Share)
		if m.Share == invalid || len(m.Mount.Source) == 0 || len(m.Mount.Type) == 0 {
			log.Warningf("ignoring mount annotations for %q because of missing required field(s)", name)
			delete(mnts, name)
			continue
		}

		// Check for duplicate mount sources.
		for name2, m2 := range mnts {
			if name != name2 && m.Mount.Source == m2.Mount.Source {
				return nil, fmt.Errorf("mounts %q and %q have the same mount source %q", m.Name, m2.Name, m.Mount.Source)
			}
		}
	}

	return &PodMountHints{Mounts: mnts}, nil
}

// MountHint represents extra information about mounts that are provided via
// annotations. They can override mount type, and provide sharing information
// so that mounts can be correctly shared inside the pod.
// It is part of the sandbox.Sandbox struct, so it must be serializable.
type MountHint struct {
	Name  string      `json:"name"`
	Share ShareType   `json:"share"`
	Mount specs.Mount `json:"mount"`
}

func (m *MountHint) setField(key, val string) error {
	switch key {
	case "source":
		if len(val) == 0 {
			return fmt.Errorf("source cannot be empty")
		}
		m.Mount.Source = val
	case "type":
		return m.setType(val)
	case "share":
		return m.setShare(val)
	case "options":
		m.Mount.Options = specutils.FilterMountOptions(strings.Split(val, ","))
	default:
		return fmt.Errorf("invalid mount annotation: %s=%s", key, val)
	}
	return nil
}

func (m *MountHint) setType(val string) error {
	switch val {
	case tmpfs.Name, Bind:
		m.Mount.Type = val
	default:
		return fmt.Errorf("invalid type %q", val)
	}
	return nil
}

func (m *MountHint) setShare(val string) error {
	switch val {
	case container.String():
		m.Share = container
	case pod.String():
		m.Share = pod
	case shared.String():
		m.Share = shared
	default:
		return fmt.Errorf("invalid share value %q", val)
	}
	return nil
}

// ShouldShareMount returns true if this mount should be configured as a shared
// mount that is shared among multiple containers in a pod.
func (m *MountHint) ShouldShareMount() bool {
	// Only support tmpfs for now. Bind mounts require a common gofer to mount
	// all shared volumes.
	return m.Mount.Type == tmpfs.Name &&
		// A shared mount should be configured for share=container too so:
		// 1. Restarting the container does not lose the tmpfs data.
		// 2. Repeated mounts in the container reuse the same tmpfs instance.
		(m.Share == container || m.Share == pod)
}

// checkCompatible verifies that shared mount is compatible with master.
// Master options must be the same or less restrictive than the container mount,
// e.g. master can be 'rw' while container mounts as 'ro'.
func (m *MountHint) checkCompatible(replica *specs.Mount) error {
	masterOpts := ParseMountOptions(m.Mount.Options)
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

func (m *MountHint) fileAccessType() config.FileAccessType {
	if m.Share == shared {
		return config.FileAccessShared
	}
	if m.ShouldShareMount() {
		return config.FileAccessExclusive
	}
	if m.Share == container {
		return config.FileAccessExclusive
	}
	return config.FileAccessShared
}

// FindMount finds the MountHint that applies to this mount.
func (p *PodMountHints) FindMount(mountSrc string) *MountHint {
	for _, m := range p.Mounts {
		if m.Mount.Source == mountSrc {
			return m
		}
	}
	return nil
}

// RootfsHint represents extra information about rootfs that are provided via
// annotations. They can provide mount source, mount type and overlay config.
type RootfsHint struct {
	Mount   specs.Mount
	Overlay config.OverlayMedium
}

func (r *RootfsHint) setSource(val string) error {
	if !filepath.IsAbs(val) {
		return fmt.Errorf("source should be an absolute path, got %q", val)
	}
	r.Mount.Source = val
	return nil
}

func (r *RootfsHint) setType(val string) error {
	switch val {
	case erofs.Name, Bind:
		r.Mount.Type = val
	default:
		return fmt.Errorf("invalid type %q", val)
	}
	return nil
}

func (r *RootfsHint) setField(key, val string) error {
	switch key {
	case "source":
		return r.setSource(val)
	case "type":
		return r.setType(val)
	case "overlay":
		return r.Overlay.Set(val)
	default:
		return fmt.Errorf("invalid rootfs annotation: %s=%s", key, val)
	}
}

// NewRootfsHint instantiates RootfsHint using spec.
func NewRootfsHint(spec *specs.Spec) (*RootfsHint, error) {
	var hint *RootfsHint
	for k, v := range spec.Annotations {
		// Look for 'dev.gvisor.spec.rootfs' annotations and parse them.
		if !strings.HasPrefix(k, RootfsPrefix) {
			continue
		}
		// Remove the prefix.
		k = k[len(RootfsPrefix):]
		if hint == nil {
			hint = &RootfsHint{}
		}
		if err := hint.setField(k, v); err != nil {
			return nil, fmt.Errorf("invalid rootfs annotation (key = %q, value = %q): %v", k, v, err)
		}
	}
	// Validate the parsed hint.
	if hint != nil {
		log.Infof("Rootfs annotations found, source: %q, type: %q, overlay: %q", hint.Mount.Source, hint.Mount.Type, hint.Overlay)
		if len(hint.Mount.Source) == 0 || len(hint.Mount.Type) == 0 {
			return nil, fmt.Errorf("rootfs annotations missing required field(s): %+v", hint)
		}
	}
	return hint, nil
}
