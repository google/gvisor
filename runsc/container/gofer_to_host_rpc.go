// Copyright 2024 The gVisor Authors.
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

package container

import (
	"fmt"
	"os"
	"runtime"
	"sync"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/urpc"
)

type openMountRequest struct {
	mount  *specs.Mount
	result *OpenMountResult
	done   chan error
}

// goferToHostRPC is an rpc server that allows the gofer process to do RPC
// calls outside of its namespace container. It is used to configure sandbox
// mounts.
type goferToHostRPC struct {
	mu                sync.Mutex
	openMountRequests chan *openMountRequest
	goferPID          int
}

// OpenMountResult is a result of the rpcp.OpenMount call.
type OpenMountResult struct {
	urpc.FilePayload
}

func (rpc *goferToHostRPC) handleRequest(req *openMountRequest) {
	defer close(req.done)
	fd, err := os.OpenFile(req.mount.Source, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		req.done <- err
		return
	}
	req.result.Files = []*os.File{fd}
}

func (rpc *goferToHostRPC) openMountThread() error {
	if err := unix.Unshare(unix.CLONE_FS); err != nil {
		return fmt.Errorf("open mount thread: unshare filesystem attributes: %w", err)
	}
	nsFd, err := os.Open(fmt.Sprintf("/proc/%d/ns/mnt", rpc.goferPID))
	if err != nil {
		return fmt.Errorf("open mount thread: open container mntns: %w", err)
	}
	defer nsFd.Close()
	if err := unix.Setns(int(nsFd.Fd()), unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("open mount thread: join container mntns: %w", err)
	}
	for req := range rpc.openMountRequests {
		rpc.handleRequest(req)
	}
	return nil
}

// OpenMount opens a specified mount and returns a file descriptor to it. It is
// used when the mount isn't accessible from the gofer user namespace.
func (rpc *goferToHostRPC) OpenMount(m *specs.Mount, res *OpenMountResult) error {
	rpc.mu.Lock()
	defer rpc.mu.Unlock()

	if rpc.openMountRequests == nil {
		rpc.openMountRequests = make(chan *openMountRequest)
		go func() {
			// This goroutine holds the current threads forever. It
			// never exits, because child processes can set
			// PDEATHSIG. It can't serve other go-routines, because
			// it does unshare CLONE_FS.
			runtime.LockOSThread()
			if err := rpc.openMountThread(); err != nil {
				for req := range rpc.openMountRequests {
					req.done <- err
				}
			}
			panic("unreachable")
		}()
	}
	req := openMountRequest{
		mount:  m,
		result: res,
		done:   make(chan error),
	}
	rpc.openMountRequests <- &req
	err := <-req.done
	return err
}
