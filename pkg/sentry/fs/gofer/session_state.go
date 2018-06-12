// Copyright 2018 Google Inc.
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
	"fmt"

	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/unet"
)

// beforeSave is invoked by stateify.
//
// TODO: Make map with private unix sockets savable.
func (e *endpointMap) beforeSave() {
	if len(e.m) != 0 {
		panic("EndpointMap with existing private unix sockets cannot be saved")
	}
}

// afterLoad is invoked by stateify.
func (s *session) afterLoad() {
	// The restore environment contains the 9p connection of this mount.
	fsys := filesystem{}
	env, ok := fs.CurrentRestoreEnvironment()
	if !ok {
		panic("failed to find restore environment")
	}
	mounts, ok := env.MountSources[fsys.Name()]
	if !ok {
		panic("failed to find mounts for filesystem type " + fsys.Name())
	}
	var args fs.MountArgs
	var found bool
	for _, mount := range mounts {
		if mount.Dev == s.connID {
			args = mount
			found = true
		}
	}
	if !found {
		panic(fmt.Sprintf("no connection for connection id %q", s.connID))
	}

	// Validate the mount flags and options.
	opts, err := options(args.Data)
	if err != nil {
		panic("failed to parse mount options: " + err.Error())
	}
	if opts.msize != s.msize {
		panic(fmt.Sprintf("new message size %v, want %v", opts.msize, s.msize))
	}
	if opts.version != s.version {
		panic(fmt.Sprintf("new version %v, want %v", opts.version, s.version))
	}
	if opts.policy != s.cachePolicy {
		panic(fmt.Sprintf("new cache policy %v, want %v", opts.policy, s.cachePolicy))
	}
	if opts.aname != s.aname {
		panic(fmt.Sprintf("new attach name %v, want %v", opts.aname, s.aname))
	}
	if opts.privateunixsocket != (s.endpoints != nil) {
		panic(fmt.Sprintf("new privateunixsocket option %v, want %v", opts.privateunixsocket, s.endpoints != nil))
	}
	if args.Flags != s.superBlockFlags {
		panic(fmt.Sprintf("new mount flags %v, want %v", args.Flags, s.superBlockFlags))
	}

	// Manually restore the connection.
	s.conn, err = unet.NewSocket(opts.fd)
	if err != nil {
		panic(fmt.Sprintf("failed to create Socket for FD %d: %v", opts.fd, err))
	}

	// Manually restore the client.
	s.client, err = p9.NewClient(s.conn, s.msize, s.version)
	if err != nil {
		panic(fmt.Sprintf("failed to connect client to server: %v", err))
	}

	// Manually restore the attach point.
	s.attach.file, err = s.client.Attach(s.aname)
	if err != nil {
		panic(fmt.Sprintf("failed to attach to aname: %v", err))
	}
}
