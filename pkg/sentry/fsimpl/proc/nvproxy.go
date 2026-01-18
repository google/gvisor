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

package proc

import (
	"fmt"
	"path"

	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/fsimpl/kernfs"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

func (fs *filesystem) addNvproxyFiles(ctx context.Context, root *auth.Credentials, k *kernel.Kernel, contents map[string]kernfs.Inode) {
	procInfo := nvproxy.ProcfsInfoFromVFS(k.VFS())
	if procInfo == nil {
		return
	}
	if _, ok := contents["driver"]; ok {
		panic("conflicting definition for /proc/driver")
	}

	// Build a dynamic filesystem tree ...
	type dir struct {
		parent   *dir
		name     string
		children map[string]any // *dir or string
	}
	dirName := func(d *dir) string {
		var b fspath.Builder
		for d.name != "" {
			b.PrependComponent(d.name)
			d = d.parent
		}
		return b.String()
	}
	nvidiaDir := &dir{
		children: make(map[string]any),
	}
	for relpath, data := range procInfo.StaticFiles {
		pit := fspath.Parse(relpath).Begin
		d := nvidiaDir
		for pit.NextOk() {
			pc := pit.String()
			subdirAny := d.children[pc]
			var subdir *dir
			if subdirAny == nil {
				subdir = &dir{
					parent:   d,
					name:     pc,
					children: make(map[string]any),
				}
				d.children[pc] = subdir
			} else {
				subdir, _ = subdirAny.(*dir)
				if subdir == nil {
					panic(fmt.Sprintf("nvproxy.ProcfsInfoFromVFS(): %s is both directory and file", path.Join(dirName(d), pc)))
				}
			}
			pit = pit.Next()
			d = subdir
		}
		pc := pit.String()
		if _, ok := d.children[pc]; ok {
			panic(fmt.Sprintf("nvproxy.ProcfsInfoFromVFS(): %s is specified multiple times", path.Join(dirName(d), pc)))
		}
		d.children[pc] = data
	}

	// ... then convert the tree to inodes.
	var inodeFromNode func(node any) kernfs.Inode
	inodeFromNode = func(node any) kernfs.Inode {
		switch node := node.(type) {
		case *dir:
			childInodes := make(map[string]kernfs.Inode)
			for childName, child := range node.children {
				childInodes[childName] = inodeFromNode(child)
			}
			return fs.newStaticDir(ctx, root, childInodes)
		case string:
			// Real /proc/driver/nvidia/registry has mode 644, but we don't
			// support writes.
			return fs.newInode(ctx, root, 0o444, newStaticFile(node))
		default:
			panic(fmt.Sprintf("unexpected node type %T", node))
		}
	}
	contents["driver"] = fs.newStaticDir(ctx, root, map[string]kernfs.Inode{
		"nvidia": inodeFromNode(nvidiaDir),
	})
}
