// Copyright 2022 The gVisor Authors.
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

// Binary main starts a fuse server that forwards filesystem operations from
// /tmp to /fuse.
package main

import (
	"os"
	"os/exec"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/hanwen/go-fuse/v2/fuse"
	"gvisor.dev/gvisor/pkg/log"
)

func main() {
	loopbackRoot, err := fs.NewLoopbackRoot("/fuse")
	if err != nil {
		log.Warningf("could not create loopback root: %v", err)
		os.Exit(1)
	}
	opts := &fuse.MountOptions{DirectMount: true, Options: []string{"default_permissions"}}
	rawFS := fs.NewNodeFS(loopbackRoot, &fs.Options{})
	server, err := fuse.NewServer(rawFS, "/tmp", opts)
	if err != nil {
		log.Warningf("could not create fuse server: %v", err)
		os.Exit(1)
	}

	go server.Serve()
	defer func() {
		server.Unmount()
		server.Wait()
	}()
	if err := server.WaitMount(); err != nil {
		// We don't shutdown the serve loop. If the mount does
		// not succeed, the loop won't work and exit.
		log.Warningf(`Could not mount fuse submount "/tmp": %v`, err)
		os.Exit(1)
	}
	cmd := exec.Command(os.Args[1], os.Args[2:]...)
	if err := cmd.Run(); err != nil {
		log.Warningf(err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}
