// Copyright 2018 The gVisor Authors.
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
	"sort"
	"strconv"
	"strings"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/cgroupfs"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devpts"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/devtmpfs"
	procvfs2 "gvisor.dev/gvisor/pkg/sentry/fsimpl/proc"
	sysvfs2 "gvisor.dev/gvisor/pkg/sentry/fsimpl/sys"
	tmpfsvfs2 "gvisor.dev/gvisor/pkg/sentry/fsimpl/tmpfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/specutils"

	// Include filesystem types that OCI spec might mount.
	_ "gvisor.dev/gvisor/pkg/sentry/fs/dev"
	_ "gvisor.dev/gvisor/pkg/sentry/fs/host"
	_ "gvisor.dev/gvisor/pkg/sentry/fs/proc"
	_ "gvisor.dev/gvisor/pkg/sentry/fs/sys"
	_ "gvisor.dev/gvisor/pkg/sentry/fs/tmpfs"
	_ "gvisor.dev/gvisor/pkg/sentry/fs/tty"
)

const (
	// Device name for root mount.
	rootDevice = "9pfs-/"

	// MountPrefix is the annotation prefix for mount hints.
	MountPrefix = "dev.gvisor.spec.mount."

	// Supported filesystems that map to different internal filesystem.
	bind   = "bind"
	nonefs = "none"
)

// tmpfs has some extra supported options that we must pass through.
var tmpfsAllowedData = []string{"mode", "size", "uid", "gid"}

// compileMounts returns the supported mounts from the mount spec, adding any
// mandatory mounts that are required by the OCI specification.
func compileMounts(spec *specs.Spec, conf *config.Config) []specs.Mount {
	// Keep track of whether proc and sys were mounted.
	var procMounted, sysMounted, devMounted, devptsMounted bool
	var mounts []specs.Mount

	// Mount all submounts from the spec.
	for _, m := range spec.Mounts {
		// Unconditionally drop any cgroupfs mounts. If requested, we'll add our
		// own below.
		if m.Type == cgroupfs.Name {
			continue
		}
		switch filepath.Clean(m.Destination) {
		case "/proc":
			procMounted = true
		case "/sys":
			sysMounted = true
		case "/dev":
			m.Type = devtmpfs.Name
			devMounted = true
		case "/dev/pts":
			m.Type = devpts.Name
			devptsMounted = true
		}
		mounts = append(mounts, m)
	}

	// Mount proc and sys even if the user did not ask for it, as the spec
	// says we SHOULD.
	var mandatoryMounts []specs.Mount

	if conf.Cgroupfs {
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        tmpfsvfs2.Name,
			Destination: "/sys/fs/cgroup",
		})
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        cgroupfs.Name,
			Destination: "/sys/fs/cgroup/memory",
			Options:     []string{"memory"},
		})
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        cgroupfs.Name,
			Destination: "/sys/fs/cgroup/cpu",
			Options:     []string{"cpu"},
		})
	}

	if !procMounted {
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        procvfs2.Name,
			Destination: "/proc",
		})
	}
	if !sysMounted {
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        sysvfs2.Name,
			Destination: "/sys",
		})
	}
	if !devMounted {
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        devtmpfs.Name,
			Destination: "/dev",
		})
	}
	if !devptsMounted {
		mandatoryMounts = append(mandatoryMounts, specs.Mount{
			Type:        devpts.Name,
			Destination: "/dev/pts",
		})
	}

	// The mandatory mounts should be ordered right after the root, in case
	// there are submounts of these mandatory mounts already in the spec.
	mounts = append(mounts[:0], append(mandatoryMounts, mounts[0:]...)...)

	return mounts
}

// goferMountData creates a slice of gofer mount data.
func goferMountData(fd int, fa config.FileAccessType, lisafs bool) []string {
	opts := []string{
		"trans=fd",
		"rfdno=" + strconv.Itoa(fd),
		"wfdno=" + strconv.Itoa(fd),
	}
	if fa == config.FileAccessShared {
		opts = append(opts, "cache=remote_revalidating")
	}
	if lisafs {
		opts = append(opts, "lisafs=true")
	}
	return opts
}

// parseAndFilterOptions parses a MountOptions slice and filters by the allowed
// keys.
func parseAndFilterOptions(opts []string, allowedKeys ...string) ([]string, error) {
	var out []string
	for _, o := range opts {
		ok, err := parseMountOption(o, allowedKeys...)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, o)
		}
	}
	return out, nil
}

func parseMountOption(opt string, allowedKeys ...string) (bool, error) {
	kv := strings.SplitN(opt, "=", 3)
	if len(kv) > 2 {
		return false, fmt.Errorf("invalid option %q", opt)
	}
	return specutils.ContainsStr(allowedKeys, kv[0]), nil
}

func mountFlags(opts []string) fs.MountSourceFlags {
	mf := fs.MountSourceFlags{}
	// Note: changes to supported options must be reflected in
	// isSupportedMountFlag() as well.
	for _, o := range opts {
		switch o {
		case "rw":
			mf.ReadOnly = false
		case "ro":
			mf.ReadOnly = true
		case "noatime":
			mf.NoAtime = true
		case "noexec":
			mf.NoExec = true
		case "bind", "rbind":
			// These are the same as a mount with type="bind".
		default:
			log.Warningf("ignoring unknown mount option %q", o)
		}
	}
	return mf
}

func isSupportedMountFlag(fstype, opt string) bool {
	switch opt {
	case "rw", "ro", "noatime", "noexec":
		return true
	}
	if fstype == tmpfsvfs2.Name {
		ok, err := parseMountOption(opt, tmpfsAllowedData...)
		return ok && err == nil
	}
	if fstype == cgroupfs.Name {
		ok, err := parseMountOption(opt, cgroupfs.SupportedMountOptions...)
		return ok && err == nil
	}
	return false
}

type fdDispenser struct {
	fds []*fd.FD
}

func (f *fdDispenser) remove() int {
	if f.empty() {
		panic("fdDispenser out of fds")
	}
	rv := f.fds[0].Release()
	f.fds = f.fds[1:]
	return rv
}

func (f *fdDispenser) empty() bool {
	return len(f.fds) == 0
}

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

// mountHint represents extra information about mounts that are provided via
// annotations. They can override mount type, and provide sharing information
// so that mounts can be correctly shared inside the pod.
type mountHint struct {
	name  string
	share shareType
	mount specs.Mount

	// root is the inode where the volume is mounted. For mounts with 'pod' share
	// the volume is mounted once and then bind mounted inside the containers.
	root *fs.Inode

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
	// Sort options so it can be compared with container mount options later on.
	sort.Strings(opts)
	m.mount.Options = opts
	return nil
}

func (m *mountHint) isSupported() bool {
	return m.mount.Type == tmpfsvfs2.Name && m.share == pod
}

// checkCompatible verifies that shared mount is compatible with master.
// For now enforce that all options are the same. Once bind mount is properly
// supported, then we should ensure the master is less restrictive than the
// container, e.g. master can be 'rw' while container mounts as 'ro'.
func (m *mountHint) checkCompatible(replica *specs.Mount) error {
	// Remove options that don't affect to mount's behavior.
	masterOpts := filterUnsupportedOptions(&m.mount)
	replicaOpts := filterUnsupportedOptions(replica)

	if len(masterOpts) != len(replicaOpts) {
		return fmt.Errorf("mount options in annotations differ from container mount, annotation: %s, mount: %s", masterOpts, replicaOpts)
	}

	sort.Strings(masterOpts)
	sort.Strings(replicaOpts)
	for i, opt := range masterOpts {
		if opt != replicaOpts[i] {
			return fmt.Errorf("mount options in annotations differ from container mount, annotation: %s, mount: %s", masterOpts, replicaOpts)
		}
	}
	return nil
}

// checkCompatibleVFS2 verifies that shared mount is compatible with master.
// Master options must be the same or less restrictive than the container mount,
// e.g. master can be 'rw' while container mounts as 'ro'.
func (m *mountHint) checkCompatibleVFS2(replica *specs.Mount) error {
	masterOpts := parseMountOptionsVFS2(m.mount.Options)
	replicaOpts := parseMountOptionsVFS2(replica.Options)

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

func filterUnsupportedOptions(mount *specs.Mount) []string {
	rv := make([]string, 0, len(mount.Options))
	for _, o := range mount.Options {
		if isSupportedMountFlag(mount.Type, o) {
			rv = append(rv, o)
		}
	}
	return rv
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

func (p *podMountHints) findMount(mount *specs.Mount) *mountHint {
	for _, m := range p.mounts {
		if m.mount.Source == mount.Source {
			return m
		}
	}
	return nil
}

type containerMounter struct {
	root *specs.Root

	// mounts is the set of submounts for the container. It's a copy from the spec
	// that may be freely modified without affecting the original spec.
	mounts []specs.Mount

	// fds is the list of FDs to be dispensed for mounts that require it.
	fds fdDispenser

	k *kernel.Kernel

	hints *podMountHints

	// productName is the value to show in
	// /sys/devices/virtual/dmi/id/product_name.
	productName string
}

func newContainerMounter(info *containerInfo, k *kernel.Kernel, hints *podMountHints, productName string) *containerMounter {
	return &containerMounter{
		root:        info.spec.Root,
		mounts:      compileMounts(info.spec, info.conf),
		fds:         fdDispenser{fds: info.goferFDs},
		k:           k,
		hints:       hints,
		productName: productName,
	}
}

func (c *containerMounter) checkDispenser() error {
	if !c.fds.empty() {
		return fmt.Errorf("not all gofer FDs were consumed, remaining: %v", c.fds)
	}
	return nil
}

func (c *containerMounter) getMountAccessType(conf *config.Config, mount *specs.Mount) config.FileAccessType {
	if hint := c.hints.findMount(mount); hint != nil {
		return hint.fileAccessType()
	}
	return conf.FileAccessMounts
}
