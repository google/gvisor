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
	"slices"
	"sync"
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/specutils"
)

// OpenMountArgs represents a mount to be opened along with its flags.
type OpenMountArgs struct {
	Mount *specs.Mount
	Flags uint32
}

type openMountRequest struct {
	args   *OpenMountArgs
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

func createIDMappedUserNS(uidMappings, gidMappings []specs.LinuxIDMapping) (*os.File, error) {
	var sysUIDMaps []syscall.SysProcIDMap
	for _, m := range uidMappings {
		sysUIDMaps = append(sysUIDMaps, syscall.SysProcIDMap{
			ContainerID: int(m.ContainerID),
			HostID:      int(m.HostID),
			Size:        int(m.Size),
		})
	}

	var sysGIDMaps []syscall.SysProcIDMap
	for _, m := range gidMappings {
		sysGIDMaps = append(sysGIDMaps, syscall.SysProcIDMap{
			ContainerID: int(m.ContainerID),
			HostID:      int(m.HostID),
			Size:        int(m.Size),
		})
	}

	proc, err := os.StartProcess("/proc/self/exe", []string{"runsc[getUsernsFD]"}, &os.ProcAttr{
		Sys: &syscall.SysProcAttr{
			Cloneflags:  unix.CLONE_NEWUSER,
			UidMappings: sysUIDMaps,
			GidMappings: sysGIDMaps,
			Ptrace:      true,
			Pdeathsig:   syscall.SIGKILL,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start helper process for userns unshare: %w", err)
	}

	defer func() {
		proc.Kill()
		proc.Wait()
	}()

	// Ensure the Go runtime is using pidfds, which are required for the
	// proc.Signal() call to correctly guarantee we opened the usernsfd
	// for the right process.
	//
	// Technically, we could fetch the handle from the pidfd directly
	// using the PIDFD_GET_USER_NAMESPACE ioctl, but this was only added
	// in kernel 6.11.
	pidfdUsed := false
	proc.WithHandle(func(pidfd uintptr) {
		pidfdUsed = true
	})
	if !pidfdUsed {
		return nil, fmt.Errorf("failed to refer to userns helper process as pidfds are not supported")
	}

	usernsFD, err := os.Open(fmt.Sprintf("/proc/%d/ns/user", proc.Pid))
	if err != nil {
		return nil, fmt.Errorf("failed to open user namespace descriptor for child PID %d: %w", proc.Pid, err)
	}

	if err := proc.Signal(syscall.Signal(0)); err != nil {
		usernsFD.Close()
		return nil, fmt.Errorf("failed to verify userns helper process validity: %w", err)
	}

	return usernsFD, nil
}

func openIDMappedMount(req *OpenMountArgs) (*os.File, error) {
	usernsFD, err := createIDMappedUserNS(req.Mount.UIDMappings, req.Mount.GIDMappings)
	if err != nil {
		return nil, err
	}
	defer usernsFD.Close()

	openTreeFlags := uint(unix.OPEN_TREE_CLONE | unix.OPEN_TREE_CLOEXEC)
	if req.Flags&unix.MS_REC != 0 {
		openTreeFlags |= unix.AT_RECURSIVE
	}

	fd, err := unix.OpenTree(unix.AT_FDCWD, req.Mount.Source, openTreeFlags)
	if err != nil {
		return nil, fmt.Errorf("open_tree(%q) failed: %w", req.Mount.Source, err)
	}

	setattrFlags := uint(unix.AT_EMPTY_PATH)
	if slices.Contains(req.Mount.Options, "ridmap") {
		setattrFlags |= unix.AT_RECURSIVE
	}

	attr := &unix.MountAttr{
		Attr_set:  unix.MOUNT_ATTR_IDMAP,
		Userns_fd: uint64(usernsFD.Fd()),
	}

	if err := unix.MountSetattr(fd, "", setattrFlags, attr); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("mount_setattr(%q) failed: %w", req.Mount.Source, err)
	}

	return os.NewFile(uintptr(fd), req.Mount.Source), nil
}

func (rpc *goferToHostRPC) handleRequest(req *openMountRequest) {
	defer close(req.done)

	var fd *os.File
	var err error

	if specutils.IsIDMappedMount(*req.args.Mount) {
		fd, err = openIDMappedMount(req.args)
	} else {
		fd, err = os.OpenFile(req.args.Mount.Source, unix.O_PATH|unix.O_CLOEXEC, 0)
	}
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
func (rpc *goferToHostRPC) OpenMount(reqArg *OpenMountArgs, res *OpenMountResult) error {
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
		args:   reqArg,
		result: res,
		done:   make(chan error),
	}
	rpc.openMountRequests <- &req
	err := <-req.done
	return err
}
