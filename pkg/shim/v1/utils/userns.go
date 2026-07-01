// Copyright 2026 The gVisor Authors.
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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// UserNamespaceConfig configures shim-side injection of a Linux user namespace
// into the OCI spec for sandbox containers. It is consulted when the shim's
// runtime options enable enable_user_namespace_annotation (see
// pkg/shim/v1/runsc/options.go) AND the sandbox's pod annotations contain
// UserNamespaceRequestAnnotation = "true". The operator-side gate exists so a
// pod cannot unilaterally request a userns when the runtime is not configured
// for one.
//
// This path exists so runsc workloads can run inside a user namespace on
// Kubernetes nodes whose runtime stack does not yet support pod.spec.hostUsers
// (KEP-127). Once kubelet+containerd plumb user namespaces to runsc directly,
// drop the annotation and use hostUsers: false instead.
// See https://github.com/google/gvisor/issues/13303.
type UserNamespaceConfig struct {
	// HostUIDBase is the lowest host UID used by the pool. Each sandbox is
	// assigned a contiguous block of size RangeSize starting at
	// HostUIDBase + slot*RangeSize.
	HostUIDBase uint32

	// HostGIDBase mirrors HostUIDBase for GIDs.
	HostGIDBase uint32

	// RangeSize is the number of UIDs/GIDs each sandbox receives. Defaults to
	// 65536, which is large enough to host typical multi-UID images.
	RangeSize uint32

	// PoolSize is the maximum number of concurrent sandboxes that can hold
	// non-overlapping ID ranges on this node. Defaults to 1000.
	PoolSize uint32

	// StateDir is the directory used to persist slot allocations across
	// shim restarts. Defaults to /run/runsc/userns-pool. Cleared on reboot
	// (since /run is tmpfs on systemd hosts), which is the desired behavior:
	// no sandboxes can survive a reboot, so all slots are free.
	StateDir string
}

// UserNamespaceRequestAnnotation is the pod-level annotation that opts the
// sandbox into shim-side user namespace injection. Set to "true" on a pod's
// metadata.annotations to request a userns. Containerd propagates this to
// the sandbox OCI spec via the runtime's pod_annotations match list (see the
// existing pod_annotations = ["dev.gvisor.*"] entry in the runtime config).
//
// This is a stopgap signal until kubelet/containerd plumb pod.spec.hostUsers
// (KEP-127) through to runsc; see https://github.com/google/gvisor/issues/13303.
const UserNamespaceRequestAnnotation = "dev.gvisor.spec.user-namespace"

// UserNamespaceSlotAnnotation records the allocated slot on the sandbox spec
// for diagnostics and for runtime introspection. The value is a decimal
// string of the slot index (0..PoolSize).
const UserNamespaceSlotAnnotation = "dev.gvisor.shim.userns.slot"

// HasUserNamespaceRequest returns true if spec.Annotations contains the opt-in
// annotation and its value is "true".
func HasUserNamespaceRequest(spec *specs.Spec) bool {
	if spec == nil || spec.Annotations == nil {
		return false
	}
	return spec.Annotations[UserNamespaceRequestAnnotation] == "true"
}

const (
	defaultUserNamespaceRangeSize = 65536
	defaultUserNamespacePoolSize  = 1000
	defaultUserNamespaceStateDir  = "/run/runsc/userns-pool"

	// sandboxIDFile holds the sandbox ID owning a slot directory. Written
	// after the slot directory is atomically created so concurrent shim
	// invocations cannot race past mkdir into a partially-claimed slot.
	sandboxIDFile = "sandbox-id"
)

// errPoolExhausted is returned when no free slot is available. Operators
// should bump UserNamespaceConfig.PoolSize.
var errPoolExhausted = errors.New("user namespace pool exhausted")

// validate fills in defaults and rejects misconfiguration. Callers should
// invoke c.validate before using any other method on UserNamespaceConfig.
func (c *UserNamespaceConfig) validate() error {
	if c.HostUIDBase == 0 || c.HostGIDBase == 0 {
		return fmt.Errorf("user_namespace_host_uid_base and user_namespace_host_gid_base must be set to non-zero values when force_user_namespace is enabled")
	}
	if c.RangeSize == 0 {
		c.RangeSize = defaultUserNamespaceRangeSize
	}
	if c.PoolSize == 0 {
		c.PoolSize = defaultUserNamespacePoolSize
	}
	if c.StateDir == "" {
		c.StateDir = defaultUserNamespaceStateDir
	}
	// Reject configurations that would map any sandbox UID outside uint32.
	maxBlocks := uint64(c.PoolSize) * uint64(c.RangeSize)
	if uint64(c.HostUIDBase)+maxBlocks > uint64(^uint32(0)) {
		return fmt.Errorf("user namespace pool overflows uint32 host UID space: host_uid_base=%d + pool_size*range_size=%d", c.HostUIDBase, maxBlocks)
	}
	if uint64(c.HostGIDBase)+maxBlocks > uint64(^uint32(0)) {
		return fmt.Errorf("user namespace pool overflows uint32 host GID space: host_gid_base=%d + pool_size*range_size=%d", c.HostGIDBase, maxBlocks)
	}
	return nil
}

// AllocateUserNamespaceSlot atomically reserves an unused slot in [0, PoolSize)
// for sandboxID, persisting the assignment under c.StateDir so it survives
// shim restarts. If sandboxID already holds a slot the existing slot is
// returned (idempotent). Returns errPoolExhausted if all slots are taken.
//
// The allocator uses os.Mkdir as the synchronization primitive: on Linux the
// kernel guarantees mkdir(2) is atomic with respect to other mkdir(2) and
// rmdir(2) callers, so two shim invocations racing on the same slot will see
// exactly one mkdir succeed.
func AllocateUserNamespaceSlot(c *UserNamespaceConfig, sandboxID string) (uint32, error) {
	if err := c.validate(); err != nil {
		return 0, err
	}
	if sandboxID == "" {
		return 0, fmt.Errorf("sandboxID is required")
	}
	if err := os.MkdirAll(c.StateDir, 0700); err != nil {
		return 0, fmt.Errorf("create userns state dir %q: %w", c.StateDir, err)
	}

	// Idempotency: if sandboxID already owns a slot, reuse it. This handles
	// retries by containerd as well as shim restarts that reissue Create.
	if slot, ok, err := findExistingSlot(c, sandboxID); err != nil {
		return 0, err
	} else if ok {
		return slot, nil
	}

	for i := uint32(0); i < c.PoolSize; i++ {
		dir := slotPath(c, i)
		if err := os.Mkdir(dir, 0700); err != nil {
			if os.IsExist(err) {
				continue
			}
			return 0, fmt.Errorf("claim slot %d (%s): %w", i, dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, sandboxIDFile), []byte(sandboxID), 0600); err != nil {
			// Best-effort cleanup. If the rmdir fails too, the slot leaks
			// until reboot (or manual operator intervention) -- safer than
			// returning a slot we couldn't tag with the owning sandbox.
			_ = os.RemoveAll(dir)
			return 0, fmt.Errorf("record sandbox owner for slot %d: %w", i, err)
		}
		return i, nil
	}
	return 0, fmt.Errorf("%w: pool_size=%d", errPoolExhausted, c.PoolSize)
}

// ReleaseUserNamespaceSlot frees the slot owned by sandboxID, if any. It is
// safe to call on a sandbox that never claimed a slot or whose slot was
// already removed; in those cases it returns nil.
func ReleaseUserNamespaceSlot(c *UserNamespaceConfig, sandboxID string) error {
	if err := c.validate(); err != nil {
		return err
	}
	if sandboxID == "" {
		return fmt.Errorf("sandboxID is required")
	}
	slot, ok, err := findExistingSlot(c, sandboxID)
	if err != nil || !ok {
		return err
	}
	return os.RemoveAll(slotPath(c, slot))
}

// findExistingSlot scans c.StateDir for a slot whose sandbox-id file matches
// sandboxID. The caller-visible state dir is small (PoolSize entries, default
// 1000) so a linear scan is acceptable.
func findExistingSlot(c *UserNamespaceConfig, sandboxID string) (uint32, bool, error) {
	entries, err := os.ReadDir(c.StateDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, false, nil
		}
		return 0, false, fmt.Errorf("scan userns state dir %q: %w", c.StateDir, err)
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		slot, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		idFile := filepath.Join(c.StateDir, e.Name(), sandboxIDFile)
		data, err := os.ReadFile(idFile)
		if err != nil {
			// A directory with no sandbox-id file is a partial claim from a
			// shim that crashed between mkdir and WriteFile. Skip it; the
			// next allocator pass will eventually overwrite it via mkdir
			// returning EEXIST. Manual operator cleanup may be needed if it
			// persists indefinitely.
			continue
		}
		if string(data) == sandboxID {
			return uint32(slot), true, nil
		}
	}
	return 0, false, nil
}

func slotPath(c *UserNamespaceConfig, slot uint32) string {
	return filepath.Join(c.StateDir, strconv.FormatUint(uint64(slot), 10))
}

// InjectUserNamespace mutates spec to add a Linux user namespace and the
// uid/gid mappings derived from c and slot. It is a no-op (returns false)
// when the spec already declares a user namespace or already contains
// uid/gid mappings, so caller-provided configuration (e.g. kubelet's
// hostUsers: false plumbing) wins.
//
// The shim must call InjectUserNamespace only on sandbox containers
// (utils.IsSandbox(spec) == true). Application/exec containers within the
// same pod inherit the sandbox's user namespace and must not have separate
// mappings; the runsc binary uses the sandbox's mappings for all
// containers in the pod.
func InjectUserNamespace(spec *specs.Spec, c *UserNamespaceConfig, slot uint32) (bool, error) {
	if err := c.validate(); err != nil {
		return false, err
	}
	if slot >= c.PoolSize {
		return false, fmt.Errorf("slot %d out of range [0, %d)", slot, c.PoolSize)
	}
	if spec.Linux == nil {
		spec.Linux = &specs.Linux{}
	}
	for _, ns := range spec.Linux.Namespaces {
		if ns.Type == specs.UserNamespace {
			return false, nil
		}
	}
	if len(spec.Linux.UIDMappings) > 0 || len(spec.Linux.GIDMappings) > 0 {
		return false, nil
	}

	hostUID := c.HostUIDBase + slot*c.RangeSize
	hostGID := c.HostGIDBase + slot*c.RangeSize

	spec.Linux.Namespaces = append(spec.Linux.Namespaces, specs.LinuxNamespace{
		Type: specs.UserNamespace,
	})
	spec.Linux.UIDMappings = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: hostUID, Size: c.RangeSize},
	}
	spec.Linux.GIDMappings = []specs.LinuxIDMapping{
		{ContainerID: 0, HostID: hostGID, Size: c.RangeSize},
	}

	if spec.Annotations == nil {
		spec.Annotations = make(map[string]string)
	}
	spec.Annotations[UserNamespaceSlotAnnotation] = strconv.FormatUint(uint64(slot), 10)
	return true, nil
}
