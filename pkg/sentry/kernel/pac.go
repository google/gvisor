// Copyright 2026 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

// PAC-KEY-CR (Bastion): a sandbox-wide ARM64 pointer-authentication key set, generated
// once at Init and serialized in the Kernel, so PAC-signed pointers survive
// checkpoint/restore. The Kernel seeds every guest address space with it by shadowing the
// promoted platform.NewAddressSpace.
//
// Why sandbox-wide (one key for all address spaces) rather than per-process: systrap pools
// and reuses stub subprocesses across address spaces, and a subprocess's guest threads also
// run gVisor's own (PAC-signed) sysmsg handler — so a thread's keys cannot be safely
// re-keyed after creation. A single sandbox-wide key makes pool reuse correct by
// construction. Cross-process PAC forgery is not enabled by this (PAC is intra-process CFI
// and guest processes have separate address spaces).

package kernel

import (
	"unsafe"

	"gvisor.dev/gvisor/pkg/rand"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// generatePACKeys fills the sandbox-wide PAC key set with random bytes. Called once from
// Init on a fresh sandbox; on restore the keys are loaded from saved state instead.
func (k *Kernel) generatePACKeys() {
	b := (*[len(k.armPACKeys) * 8]byte)(unsafe.Pointer(&k.armPACKeys))[:]
	if _, err := rand.Read(b); err != nil {
		panic("kernel: failed to generate ARM64 PAC keys: " + err.Error())
	}
}

// NewAddressSpace shadows the promoted platform.NewAddressSpace to seed each guest address
// space with the sandbox-wide ARM64 PAC keys, so PAC survives checkpoint/restore. Platforms
// that cannot install PAC keys (amd64, and KVM until it implements the setter) fall back to
// the plain address space and ignore the keys.
func (k *Kernel) NewAddressSpace() (platform.AddressSpace, error) {
	if m, ok := k.Platform.(interface {
		NewAddressSpaceWithPAC(keys [10]uint64) (platform.AddressSpace, error)
	}); ok {
		return m.NewAddressSpaceWithPAC(k.armPACKeys)
	}
	return k.Platform.NewAddressSpace()
}
