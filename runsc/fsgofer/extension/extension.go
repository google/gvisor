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

// Package extension defines registration hooks for custom filesystem gofer
// extensions. The stock fsgofer handles any mount no Extension claims.
package extension

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/seccomp"
)

// Extension is implemented by alternative LisaFS backends. The first
// registered Extension whose TryHandleMount returns a non-nil implementation
// handles the mount.
type Extension interface {
	// Name identifies the extension in log messages.
	Name() string

	// TryHandleMount returns a LisaFS connection implementation and options for
	// the given mount, or (nil, lisafs.ConnectionOpts{}, nil) if this extension
	// does not handle it. A non-nil error means the extension claims the mount
	// but failed to initialize.
	//
	// mount is nil for the root filesystem (root is not present in
	// spec.Mounts). Per-sandbox config may be read from spec.Annotations.
	//
	// All returned connections run on one shared lisafs.Server so server-side
	// tree synchronization is preserved across stock and extension-backed
	// mounts.
	TryHandleMount(spec *specs.Spec, mount *specs.Mount, mountPath string, readonly bool) (lisafs.ConnectionImpl, lisafs.ConnectionOpts, error)

	// SeccompRules returns additional rules to merge into the stock
	// gofer's seccomp allowlist.
	SeccompRules() seccomp.SyscallRules
}

var registered []Extension

// Register adds e to the extension list. Must be called during init or
// early in main, before Registered is iterated.
func Register(e Extension) {
	registered = append(registered, e)
}

// Registered returns all registered extensions in registration order.
func Registered() []Extension {
	return registered
}
