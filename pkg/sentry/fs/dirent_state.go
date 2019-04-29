// Copyright 2018 The gVisor Authors.
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

package fs

import (
	"fmt"
	"sync/atomic"

	"gvisor.googlesource.com/gvisor/pkg/refs"
)

// beforeSave is invoked by stateify.
func (d *Dirent) beforeSave() {
	// Refuse to save if the file is on a non-virtual file system and has
	// already been deleted (but still has open fds, which is why the Dirent
	// is still accessible). We know the the restore re-opening of the file
	// will always fail. This condition will last until all the open fds and
	// this Dirent are closed and released.
	//
	// Such "dangling" open files on virtual file systems (e.g., tmpfs) is
	// OK to save as their restore does not require re-opening the files.
	//
	// Note that this is rejection rather than failure---it would be
	// perfectly OK to save---we are simply disallowing it here to prevent
	// generating non-restorable state dumps. As the program continues its
	// execution, it may become allowed to save again.
	if !d.Inode.IsVirtual() && atomic.LoadInt32(&d.deleted) != 0 {
		n, _ := d.FullName(nil /* root */)
		panic(ErrSaveRejection{fmt.Errorf("deleted file %q still has open fds", n)})
	}
}

// saveChildren is invoked by stateify.
func (d *Dirent) saveChildren() map[string]*Dirent {
	c := make(map[string]*Dirent)
	for name, w := range d.children {
		if rc := w.Get(); rc != nil {
			// Drop the reference count obtain in w.Get()
			rc.DecRef()

			cd := rc.(*Dirent)
			if cd.IsNegative() {
				// Don't bother saving negative Dirents.
				continue
			}
			c[name] = cd
		}
	}
	return c
}

// loadChildren is invoked by stateify.
func (d *Dirent) loadChildren(children map[string]*Dirent) {
	d.children = make(map[string]*refs.WeakRef)
	for name, c := range children {
		d.children[name] = refs.NewWeakRef(c, nil)
	}
}

// afterLoad is invoked by stateify.
func (d *Dirent) afterLoad() {
	if d.userVisible {
		allDirents.add(d)
	}
}
