// Copyright 2026 The gVisor Authors.
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

// Package amdgpu validates AMD GPU device grants and snapshots the host sysfs
// surface that ROCm reads, for reproduction in the sandbox.
package amdgpu

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Path is where the sandbox chroot holds the snapshot for the sentry.
const Path = "/var/lib/gvisor/amdgpu_sysfs.json"

// Device is an AMD GPU device granted by the OCI spec.
type Device struct {
	Path  string
	Major uint32
	Minor uint32
}

// Snapshot is a read-only sysfs subtree, with paths relative to /sys.
type Snapshot struct {
	Files map[string]string
	// Links maps symlinks to their targets.
	Links map[string]string
	// Dirs lists directories that may have no other entries.
	Dirs []string
	// GPUIDs maps the granted DRM render minors to their KFD GPU IDs.
	GPUIDs map[uint32]uint32
}

// IsDevicePath reports whether p names /dev/kfd or a DRM render node.
func IsDevicePath(p string) bool {
	if p == "/dev/kfd" {
		return true
	}
	n, ok := strings.CutPrefix(p, "/dev/dri/renderD")
	minor, err := strconv.ParseUint(n, 10, 32)
	return ok && err == nil && minor >= 128 && strconv.FormatUint(minor, 10) == n
}

// ValidateDevice checks that d is the host's KFD device or an amdgpu render
// node.
func ValidateDevice(hostRoot string, d Device) error {
	if !IsDevicePath(d.Path) {
		return fmt.Errorf("%q is not an AMD GPU compute device", d.Path)
	}
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(hostRoot, d.Path), &st); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFCHR || unix.Major(uint64(st.Rdev)) != d.Major || unix.Minor(uint64(st.Rdev)) != d.Minor {
		return fmt.Errorf("%s is not character device %d:%d", d.Path, d.Major, d.Minor)
	}
	if d.Path == "/dev/kfd" {
		return nil
	}
	driver, err := filepath.EvalSymlinks(filepath.Join(hostRoot, "sys/class/drm", path.Base(d.Path), "device/driver"))
	if err != nil {
		return err
	}
	if filepath.Base(driver) != "amdgpu" {
		return fmt.Errorf("%s is bound to the %s driver, not amdgpu", d.Path, filepath.Base(driver))
	}
	return nil
}

// Save serializes the snapshot to dst.
func (s *Snapshot) Save(dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0644)
}

// Load deserializes a snapshot from src.
func Load(src string) (*Snapshot, error) {
	b, err := os.ReadFile(src)
	if err != nil {
		return nil, err
	}
	var s Snapshot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("unmarshaling AMD GPU sysfs snapshot %q: %w", src, err)
	}
	return &s, nil
}

const (
	kfdDir   = "devices/virtual/kfd/kfd"
	topology = kfdDir + "/topology"
)

// gfxTargetVersions lists the GPU architectures the proxy has been qualified
// on, by KFD gfx_target_version: gfx942 (MI300) and gfx950 (MI355).
var gfxTargetVersions = map[string]bool{"90402": true, "90500": true}

// pciAttrs are the PCI device attributes reproduced for each render node.
var pciAttrs = []string{"class", "vendor", "device", "subsystem_vendor", "subsystem_device", "revision", "numa_node", "local_cpus", "local_cpulist", "uevent"}

// Collect snapshots the KFD topology and the identity of the granted render
// nodes. The topology is taken whole: ROCm's thunk enumerates its nodes by
// dense index, and by itself skips GPUs whose render node it cannot open.
func Collect(sysRoot string, devices []Device) (*Snapshot, error) {
	s := &Snapshot{Files: map[string]string{}, Links: map[string]string{}, GPUIDs: map[uint32]uint32{}}
	for _, name := range []string{"dev", "uevent"} {
		if err := s.readFile(sysRoot, kfdDir+"/"+name); err != nil {
			return nil, err
		}
	}
	err := filepath.WalkDir(filepath.Join(sysRoot, topology), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(sysRoot, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			s.Dirs = append(s.Dirs, rel)
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		return s.readFile(sysRoot, rel)
	})
	if err != nil {
		return nil, err
	}
	s.Links["class/kfd/kfd"] = "../../" + kfdDir

	renders := map[uint32]bool{}
	for _, d := range devices {
		if d.Path == "/dev/kfd" {
			continue
		}
		renders[d.Minor] = true
		if err := s.addRenderNode(sysRoot, d); err != nil {
			return nil, err
		}
	}
	nodes, err := os.ReadDir(filepath.Join(sysRoot, topology, "nodes"))
	if err != nil {
		return nil, err
	}
	for _, node := range nodes {
		base := topology + "/nodes/" + node.Name()
		props := parseProperties(s.Files[base+"/properties"])
		if props["simd_count"] == "0" {
			continue // CPU node.
		}
		// The proxy does not forward the SVM ioctls.
		s.Files[base+"/properties"] = withoutSVMCapability(s.Files[base+"/properties"])
		minor, _ := strconv.ParseUint(props["drm_render_minor"], 10, 32)
		if !renders[uint32(minor)] {
			continue
		}
		if !gfxTargetVersions[props["gfx_target_version"]] {
			return nil, fmt.Errorf("renderD%d has gfx_target_version %q; only gfx942 (90402) and gfx950 (90500) are supported", minor, props["gfx_target_version"])
		}
		id, err := strconv.ParseUint(strings.TrimSpace(s.Files[base+"/gpu_id"]), 10, 32)
		if err != nil || id == 0 {
			return nil, fmt.Errorf("invalid gpu_id for KFD node %s", node.Name())
		}
		s.GPUIDs[uint32(minor)] = uint32(id)
	}
	for minor := range renders {
		if s.GPUIDs[minor] == 0 {
			return nil, fmt.Errorf("renderD%d is not a KFD GPU", minor)
		}
	}
	return s, nil
}

func (s *Snapshot) readFile(sysRoot, rel string) error {
	f, err := os.Open(filepath.Join(sysRoot, rel))
	if err != nil {
		return err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1<<16))
	if err != nil {
		return err
	}
	s.Files[rel] = string(b)
	return nil
}

func (s *Snapshot) addRenderNode(sysRoot string, d Device) error {
	name := path.Base(d.Path)
	class := "class/drm/" + name
	resolved, err := filepath.EvalSymlinks(filepath.Join(sysRoot, class, "device"))
	if err != nil {
		return err
	}
	pci, err := filepath.Rel(sysRoot, resolved)
	if err != nil || !strings.HasPrefix(pci, "devices/pci") {
		return fmt.Errorf("%s: unexpected device path %q", name, resolved)
	}
	for _, attr := range pciAttrs {
		if err := s.readFile(sysRoot, pci+"/"+attr); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	render := pci + "/drm/" + name
	for _, attr := range []string{"dev", "uevent"} {
		if err := s.readFile(sysRoot, render+"/"+attr); err != nil {
			return err
		}
	}
	// libdrm identifies the GPU behind a render node FD by the card entry
	// next to it (drmGetMinorNameForFD). The card node itself is not exposed.
	entries, err := os.ReadDir(filepath.Join(sysRoot, pci, "drm"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if n, ok := strings.CutPrefix(e.Name(), "card"); ok && e.IsDir() && strings.Trim(n, "0123456789") == "" {
			s.Dirs = append(s.Dirs, pci+"/drm/"+e.Name())
		}
	}
	// Symlink targets are relative to their location, as in the kernel.
	up := func(p string) string { return strings.Repeat("../", strings.Count(p, "/")+1) }
	bdf := path.Base(pci)
	s.Links[render+"/device"] = "../.."
	s.Links[render+"/subsystem"] = up(render) + "class/drm"
	s.Links[class] = "../../" + render
	s.Links[fmt.Sprintf("dev/char/%d:%d", d.Major, d.Minor)] = "../../" + render
	s.Links[pci+"/subsystem"] = up(pci) + "bus/pci"
	s.Links[pci+"/driver"] = up(pci) + "bus/pci/drivers/amdgpu"
	s.Links["bus/pci/devices/"+bdf] = "../../../" + pci
	s.Links["bus/pci/drivers/amdgpu/"+bdf] = "../../../../" + pci
	return nil
}

// parseProperties parses a KFD topology properties file of "name value"
// lines.
func parseProperties(data string) map[string]string {
	props := map[string]string{}
	for _, line := range strings.Split(data, "\n") {
		if name, value, ok := strings.Cut(line, " "); ok {
			props[name] = value
		}
	}
	return props
}

// withoutSVMCapability clears HSA_CAP_SVMAPI_SUPPORTED in a node's
// capability property.
func withoutSVMCapability(data string) string {
	lines := strings.Split(data, "\n")
	for i, line := range lines {
		if value, ok := strings.CutPrefix(line, "capability "); ok {
			if bits, err := strconv.ParseUint(value, 10, 64); err == nil {
				lines[i] = "capability " + strconv.FormatUint(bits&^0x08000000, 10)
			}
		}
	}
	return strings.Join(lines, "\n")
}
