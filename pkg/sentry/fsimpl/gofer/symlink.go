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

package gofer

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
)

func (d *dentry) isSymlink() bool {
	return d.fileType() == linux.S_IFLNK
}

// Precondition: d.isSymlink().
func (d *dentry) readlink(ctx context.Context, mnt *vfs.Mount) (string, error) {
	if d.fs.opts.interop != InteropModeShared {
		d.touchAtime(mnt)
		d.dataMu.Lock()
		if d.haveTarget {
			target := d.target
			d.dataMu.Unlock()
			return target, nil
		}
	}
	var target string
	var err error
	if d.fs.opts.lisaEnabled {
		target, err = d.controlFDLisa.ReadLinkAt(ctx)
	} else {
		target, err = d.file.readlink(ctx)
	}
	if d.fs.opts.interop != InteropModeShared {
		if err == nil {
			d.haveTarget = true
			d.target = target
		}
		d.dataMu.Unlock() // +checklocksforce: guaranteed locked from above.
	}
	return target, err
}
