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

// Package provider defines an interface for pluggable gofer filesystem
// providers. A Provider serves LisaFS connections for specific mounts,
// allowing custom filesystem implementations (e.g. network-backed storage,
// encrypted filesystems, tiered caches) without forking the runsc binary.
//
// The stock fsgofer remains the default for all mounts. Providers only
// serve mounts they claim by returning a non-nil server from NewServer.
//
// This follows the same pattern as socket.Provider: the caller iterates
// registered providers and uses the first one that returns a non-nil
// result, falling back to the stock implementation when none match.
package provider

import (
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/lisafs"
	"gvisor.dev/gvisor/pkg/seccomp"
	"gvisor.dev/gvisor/runsc/specutils"
)

// Provider is the interface that pluggable gofer filesystem providers
// implement. For each mount, the gofer iterates registered providers
// and calls NewServer. The first provider that returns a non-nil server
// handles the mount. If all providers return nil, the stock fsgofer
// handles it.
type Provider interface {
	// Name returns a human-readable name for this provider, used in
	// log messages (e.g. "storagefs", "encryptedfs", "3bfs").
	Name() string

	// NewServer creates a LisaFS server for the mount at mountPath, or
	// returns (nil, nil) if this provider does not handle the mount.
	// A non-nil error means the provider claims the mount but failed.
	//
	// spec is the sandbox's OCI runtime spec; providers read per-mount
	// configuration from spec.Annotations. mountPath is the resolved,
	// absolute destination inside the container (e.g. "/storage/data").
	// conf describes the mount's overlay and filesystem configuration.
	// readonly indicates whether the mount was configured as read-only.
	NewServer(spec *specs.Spec, mountPath string, conf specutils.GoferMountConf, readonly bool) (*lisafs.Server, error)

	// SeccompRules returns additional seccomp rules that this provider
	// requires beyond the stock gofer allowlist. The rules are merged
	// into the gofer's seccomp program before installation. Return a
	// zero-value SyscallRules (Size() == 0) if no extra rules are needed.
	//
	// SeccompRules is called once during gofer startup, before any
	// mounts are served. Rules from all registered providers are merged
	// regardless of which mounts they will actually handle.
	SeccompRules() seccomp.SyscallRules
}

// registered holds all providers in registration order.
// Must be populated during init or early in main, before the gofer
// installs seccomp filters or starts serving connections.
var registered []Provider

// Register adds a Provider. Providers are consulted in registration
// order; the first to return a non-nil server wins. Must be called
// during init or early in main, before concurrent use.
func Register(p Provider) {
	registered = append(registered, p)
}

// Registered returns all registered providers.
func Registered() []Provider {
	return registered
}
