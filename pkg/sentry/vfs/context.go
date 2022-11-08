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
	"gvisor.dev/gvisor/pkg/context"
)

// contextID is this package's type for context.Context.Value keys.
type contextID int

const (
	// CtxMountNamespace is a Context.Value key for a MountNamespace.
	CtxMountNamespace contextID = iota

	// CtxRoot is a Context.Value key for a VFS root.
	CtxRoot
)

// MountNamespaceFromContext returns the MountNamespace used by ctx. If ctx is
// not associated with a MountNamespace, MountNamespaceFromContext returns nil.
//
// A reference is taken on the returned MountNamespace.
func MountNamespaceFromContext(ctx context.Context) *MountNamespace {
	if v := ctx.Value(CtxMountNamespace); v != nil {
		return v.(*MountNamespace)
	}
	return nil
}

type mountNamespaceContext struct {
	context.Context
	mntns *MountNamespace
}

// Value implements Context.Value.
func (mc mountNamespaceContext) Value(key any) any {
	switch key {
	case CtxMountNamespace:
		mc.mntns.IncRef()
		return mc.mntns
	default:
		return mc.Context.Value(key)
	}
}

// WithMountNamespace returns a copy of ctx with the given MountNamespace.
func WithMountNamespace(ctx context.Context, mntns *MountNamespace) context.Context {
	return &mountNamespaceContext{
		Context: ctx,
		mntns:   mntns,
	}
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

type rootContext struct {
	context.Context
	root VirtualDentry
}

// WithRoot returns a copy of ctx with the given root.
func WithRoot(ctx context.Context, root VirtualDentry) context.Context {
	return &rootContext{
		Context: ctx,
		root:    root,
	}
}

// Value implements Context.Value.
func (rc rootContext) Value(key any) any {
	switch key {
	case CtxRoot:
		rc.root.IncRef()
		return rc.root
	default:
		return rc.Context.Value(key)
	}
}
