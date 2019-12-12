// Copyright 2019 The gVisor Authors.
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

package vfs

import (
	"gvisor.dev/gvisor/pkg/sentry/context"
)

// contextID is this package's type for context.Context.Value keys.
type contextID int

const (
	// CtxMountNamespace is a Context.Value key for a MountNamespace.
	CtxMountNamespace contextID = iota

	// CtxRoot is a Context.Value key for a VFS root.
	CtxRoot
)

// MountNamespaceFromContext returns the MountNamespace used by ctx. It does
// not take a reference on the returned MountNamespace. If ctx is not
// associated with a MountNamespace, MountNamespaceFromContext returns nil.
func MountNamespaceFromContext(ctx context.Context) *MountNamespace {
	if v := ctx.Value(CtxMountNamespace); v != nil {
		return v.(*MountNamespace)
	}
	return nil
}

// RootFromContext returns the VFS root used by ctx. It takes a reference on
// the returned VirtualDentry. If ctx does not have a specific VFS root,
// RootFromContext returns a zero-value VirtualDentry.
func RootFromContext(ctx context.Context) VirtualDentry {
	if v := ctx.Value(CtxRoot); v != nil {
		return v.(VirtualDentry)
	}
	return VirtualDentry{}
}
