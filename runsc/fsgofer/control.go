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

package fsgofer

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"gvisor.googlesource.com/gvisor/pkg/control/server"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/p9"
	"gvisor.googlesource.com/gvisor/pkg/unet"
	"gvisor.googlesource.com/gvisor/pkg/urpc"
)

// Controller manages the fsgofer's control server.
type Controller struct {
	// api holds the control server's URPC endpoints.
	api api

	// srv is the control server.
	srv *server.Server
}

// NewController creates a new Controller and starts it listenting
func NewController(fd int, rootBundleDir string) (*Controller, error) {
	if !filepath.IsAbs(rootBundleDir) {
		return nil, fmt.Errorf("NewController should receive an absolute bundle dir path, but got %q", rootBundleDir)
	}

	srv, err := server.CreateFromFD(fd)
	if err != nil {
		return nil, err
	}

	cr := &Controller{srv: srv}
	cr.api.rootBundleDir = rootBundleDir
	cr.api.bundleDirs = make(map[string]string)
	srv.Register(&cr.api)

	if err := srv.StartServing(); err != nil {
		return nil, err
	}

	return cr, nil
}

// Wait waits for all the p9 servers to finish, then shuts down the control
// server.
func (cr *Controller) Wait() {
	cr.api.p9wg.Wait()
	cr.srv.Stop()
	log.Infof("All 9P servers exited.")
}

// Serve starts serving each Attacher in ats via its corresponding file
// descriptor in ioFDs. This takes ownership of the FDs in ioFDs.
func (cr *Controller) Serve(ats []p9.Attacher, ioFDs []int) error {
	if len(ats) != len(ioFDs) {
		return fmt.Errorf("number of attach points does not match the number of IO FDs (%d and %d)", len(ats), len(ioFDs))
	}
	for i, _ := range ats {
		cr.api.serve(ats[i], os.NewFile(uintptr(ioFDs[i]), "io fd"))
	}
	return nil
}

// api URPC methods.
const (
	// AddBundleDirs readies the gofer to serve from a new bundle
	// directory. It should be called during runsc create.
	AddBundleDirs = "api.AddBundleDirs"

	// ServeDirectory serves a new directory via the fsgofer. It should be
	// called during runsc start.
	ServeDirectory = "api.ServeDirectory"
)

// API defines and implements the URPC endpoints for the gofer.
type api struct {
	// p9wg waits for all the goroutines serving the sentry via p9. When its
	// counter is 0, the gofer is out of work and exits.
	p9wg sync.WaitGroup

	// bundleDirs maps from container ID to bundle directory for each
	// container.
	bundleDirs map[string]string

	// rootBundleDir is the bundle directory of the root container.
	rootBundleDir string
}

// AddBundleDirsRequest is the URPC argument to AddBundleDirs.
type AddBundleDirsRequest struct {
	// BundleDirs is a map of container IDs to bundle directories to add to
	// the gofer.
	BundleDirs map[string]string
}

// AddBundleDirsRequest adds bundle directories that for the gofer to serve.
func (api *api) AddBundleDirs(req *AddBundleDirsRequest, _ *struct{}) error {
	log.Debugf("fsgofer.AddBundleDirs")
	for cid, bd := range req.BundleDirs {
		if _, ok := api.bundleDirs[cid]; ok {
			return fmt.Errorf("fsgofer already has a bundleDir for container %q", cid)
		}
		api.bundleDirs[cid] = bd
	}
	return nil
}

// ServeDirectoryRequest is the URPC argument to ServeDirectory.
type ServeDirectoryRequest struct {
	// Dir is the absolute path to a directory to be served to the sentry.
	Dir string

	// IsReadOnly specifies whether the directory should be served in
	// read-only mode.
	IsReadOnly bool

	// CID is the container ID of the container that needs to serve a
	// directory.
	CID string

	// FilePayload contains the socket over which the sentry will request
	// files from Dir.
	urpc.FilePayload
}

// ServeDirectory begins serving a directory via a file descriptor for the
// sentry. Directories must be added via AddBundleDirsRequest before
// ServeDirectory is called.
func (api *api) ServeDirectory(req *ServeDirectoryRequest, _ *struct{}) error {
	log.Debugf("fsgofer.ServeDirectory: %+v", req)

	if req.Dir == "" {
		return fmt.Errorf("ServeDirectory should receive a directory argument, but was empty")
	}
	if req.CID == "" {
		return fmt.Errorf("ServeDirectory should receive a CID argument, but was empty")
	}
	// Prevent CIDs containing ".." from confusing the sentry when creating
	// /containers/<cid> directory.
	// TODO: Once we have multiple independant roots, this
	// check won't be necessary.
	if filepath.Clean(req.CID) != req.CID {
		return fmt.Errorf("container ID shouldn't contain directory traversals such as \"..\": %q", req.CID)
	}
	if nFiles := len(req.FilePayload.Files); nFiles != 1 {
		return fmt.Errorf("ServeDirectory should receive 1 file descriptor, but got %d", nFiles)
	}

	bd, ok := api.bundleDirs[req.CID]
	if !ok {
		// If there's no entry in bundleDirs for the container ID, this
		// is the root container.
		bd = api.rootBundleDir
	}

	// Relative paths are served relative to the bundle directory.
	absDir := req.Dir
	if !filepath.IsAbs(absDir) {
		absDir = filepath.Join(bd, req.Dir)
	}

	// Create the attach point and start serving.
	at := NewAttachPoint(absDir, Config{
		ROMount:          req.IsReadOnly,
		LazyOpenForWrite: true,
	})
	api.serve(at, req.FilePayload.Files[0])

	return nil
}

// serve begins serving a directory via a file descriptor.
func (api *api) serve(at p9.Attacher, ioFile *os.File) {
	api.p9wg.Add(1)
	go func() {
		socket, err := unet.NewSocket(int(ioFile.Fd()))
		if err != nil {
			panic(fmt.Sprintf("err creating server on FD %d: %v", ioFile.Fd(), err))
		}
		s := p9.NewServer(at)
		if err := s.Handle(socket); err != nil {
			panic(fmt.Sprintf("P9 server returned error. Gofer is shutting down. FD: %d, err: %v", ioFile.Fd(), err))
		}
		api.p9wg.Done()
	}()
}
