// Copyright 2021 The gVisor Authors.
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

// Package securityhooks provides a set of hooks which can be used to get
// notifications about certain events in the Sentry.
package securityhooks

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/fsbridge"
	"gvisor.dev/gvisor/pkg/sentry/memmap"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	// CtxSecurityHooks is a Context.Value key for a Kernel.SecurityHooks
	CtxSecurityHooks = iota
)

// VMA describes a memory mapping.
type VMA struct {
	RealPerm usermem.AccessType
	MaxPerms usermem.AccessType
	ID       memmap.MappingIdentity

	Start usermem.Addr
	End   usermem.Addr
}

// SecurityHooks is an interface containing security hooks that are called at
// specific events in the Sentry.
type SecurityHooks interface {
	// OnTaskNew is called when a new kernel.Task is created.
	OnTaskNew(ctx context.Context)
	// OnTaskExit is called when a group leader exits.
	OnTaskExit(ctx context.Context)
	// TaskExecve is called before loading a new binary.
	//
	// FIXME(b/173152046): the loader module isn't imported here to avoid
	// circular dependencies. We probably need to move the declaration of
	// LoadArgs in a new sub-package.
	OnTaskExecve(ctx context.Context, args interface{} /* *loader.LoadArgs */) error
	// OnFileMProtect is called before changing protection on a memory region.
	OnFileMProtect(ctx context.Context, vma *VMA, perms usermem.AccessType) error
	// OnFileMMap is called before mapping a new memory region.
	OnFileMMap(ctx context.Context, file fsbridge.File, perms usermem.AccessType, flags int32) error
}

var securityModules = make(map[string]SecurityHooks)

// RegisterModule registers a set of security hooks.
func RegisterModule(name string, hooks SecurityHooks) {
	securityModules[name] = hooks
}

// LookupModule finds a module by name.
func LookupModule(name string) SecurityHooks {
	return securityModules[name]
}
