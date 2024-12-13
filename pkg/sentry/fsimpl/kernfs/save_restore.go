// Copyright 2020 The gVisor Authors.
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

package kernfs

import (
	"context"

	"gvisor.dev/gvisor/pkg/refs"
)

// afterLoad is invoked by stateify.
func (d *Dentry) afterLoad(context.Context) {
	if d.refs.Load() >= 0 {
		refs.Register(d)
		d.inode.AddInvalidateCallback(d)
	}
}

// afterLoad is invoked by stateify.
func (i *inodePlatformFile) afterLoad(context.Context) {
	if i.fileMapper.IsInited() {
		// Ensure that we don't call i.fileMapper.Init() again.
		i.fileMapperInitOnce.Do(func() {})
	}
}

// saveParent is called by stateify.
func (d *Dentry) saveParent() *Dentry {
	return d.parent.Load()
}

// loadParent is called by stateify.
func (d *Dentry) loadParent(_ context.Context, parent *Dentry) {
	d.parent.Store(parent)
}
