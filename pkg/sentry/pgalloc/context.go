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

package pgalloc

import (
	"gvisor.dev/gvisor/pkg/context"
)

// contextID is this package's type for context.Context.Value keys.
type contextID int

const (
	// CtxMemoryFile is a Context.Value key for a MemoryFile.
	CtxMemoryFile contextID = iota

	// CtxMemoryFileProvider is a Context.Value key for a MemoryFileProvider.
	CtxMemoryFileProvider

	// CtxMemoryCgroupID is the memory cgroup id which the task belongs to.
	CtxMemoryCgroupID
)

// MemoryFileFromContext returns the MemoryFile used by ctx, or nil if no such
// MemoryFile exists.
func MemoryFileFromContext(ctx context.Context) *MemoryFile {
	if v := ctx.Value(CtxMemoryFile); v != nil {
		return v.(*MemoryFile)
	}
	return nil
}

// MemoryFileProviderFromContext returns the MemoryFileProvider used by ctx, or nil if no such
// MemoryFileProvider exists.
func MemoryFileProviderFromContext(ctx context.Context) MemoryFileProvider {
	if v := ctx.Value(CtxMemoryFileProvider); v != nil {
		return v.(MemoryFileProvider)
	}
	return nil
}

// MemoryCgroupIDFromContext returns the memory cgroup id of the ctx, or
// zero if the ctx does not belong to any memory cgroup.
func MemoryCgroupIDFromContext(ctx context.Context) uint32 {
	if v := ctx.Value(CtxMemoryCgroupID); v != nil {
		return v.(uint32)
	}
	return 0
}
