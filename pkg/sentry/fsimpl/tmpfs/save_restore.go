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

package tmpfs

// afterLoad is called by stateify.
func (fs *filesystem) afterLoad() {
	if fs.privateMF {
		// TODO(b/271612187): Add S/R support.
		panic("S/R not supported for private memory files")
	}
	fs.mf = fs.mfp.MemoryFile()
}

// saveParent is called by stateify.
func (d *dentry) saveParent() *dentry {
	return d.parent.Load()
}

// saveParent is called by stateify.
func (d *dentry) loadParent(parent *dentry) {
	d.parent.Store(parent)
}
