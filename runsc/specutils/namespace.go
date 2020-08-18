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

package specutils

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/syndtr/gocapability/capability"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/log"
)

// nsCloneFlag returns the clone flag that can be used to set a namespace of
// the given type.
func nsCloneFlag(nst specs.LinuxNamespaceType) uintptr {
	switch nst {
	case specs.IPCNamespace:
		return unix.CLONE_NEWIPC
	case specs.MountNamespace:
		return unix.CLONE_NEWNS
	case specs.NetworkNamespace:
		return unix.CLONE_NEWNET
	case specs.PIDNamespace:
		return unix.CLONE_NEWPID
	case specs.UTSNamespace:
		return unix.CLONE_NEWUTS
	case specs.UserNamespace:
		return unix.CLONE_NEWUSER
	case specs.CgroupNamespace:
		return unix.CLONE_NEWCGROUP
	default:
		panic(fmt.Sprintf("unknown namespace %v", nst))
	}
}

// nsPath returns the path of the namespace for the current process and the
// given namespace.
func nsPath(nst specs.LinuxNamespaceType) string {
	base := "/proc/self/ns"
	switch nst {
	case specs.CgroupNamespace:
		return filepath.Join(base, "cgroup")
	case specs.IPCNamespace:
		return filepath.Join(base, "ipc")
	case specs.MountNamespace:
		return filepath.Join(base, "mnt")
	case specs.NetworkNamespace:
		return filepath.Join(base, "net")
	case specs.PIDNamespace:
		return filepath.Join(base, "pid")
	case specs.UserNamespace:
		return filepath.Join(base, "user")
	case specs.UTSNamespace:
		return filepath.Join(base, "uts")
	default:
		panic(fmt.Sprintf("unknown namespace %v", nst))
	}
}

// GetNS returns true and the namespace with the given type from the slice of
// namespaces in the spec.  It returns false if the slice does not contain a
// namespace with the type.
func GetNS(nst specs.LinuxNamespaceType, s *specs.Spec) (specs.LinuxNamespace, bool) {
	if s.Linux == nil {
		return specs.LinuxNamespace{}, false
	}
	for _, ns := range s.Linux.Namespaces {
		if ns.Type == nst {
			return ns, true
		}
	}
	return specs.LinuxNamespace{}, false
}

// FilterNS returns a slice of namespaces from the spec with types that match
// those in the `filter` slice.
func FilterNS(filter []specs.LinuxNamespaceType, s *specs.Spec) []specs.LinuxNamespace {
	if s.Linux == nil {
		return nil
	}
	var out []specs.LinuxNamespace
	for _, nst := range filter {
		if ns, ok := GetNS(nst, s); ok {
			out = append(out, ns)
		}
	}
	return out
}

// setNS sets the namespace of the given type.  It must be called with
// OSThreadLocked.
func setNS(fd, nsType uintptr) error {
	if _, _, err := syscall.RawSyscall(unix.SYS_SETNS, fd, nsType, 0); err != 0 {
		return err
	}
	return nil
}

// ApplyNS applies the namespace on the current thread and returns a function
// that will restore the namespace to the original value.
//
// Preconditions: Must be called with os thread locked.
func ApplyNS(ns specs.LinuxNamespace) (func(), error) {
	log.Infof("Applying namespace %v at path %q", ns.Type, ns.Path)
	newNS, err := os.Open(ns.Path)
	if err != nil {
		return nil, fmt.Errorf("error opening %q: %v", ns.Path, err)
	}
	defer newNS.Close()

	// Store current namespace to restore back.
	curPath := nsPath(ns.Type)
	oldNS, err := os.Open(curPath)
	if err != nil {
		return nil, fmt.Errorf("error opening %q: %v", curPath, err)
	}

	// Set namespace to the one requested and setup function to restore it back.
	flag := nsCloneFlag(ns.Type)
	if err := setNS(newNS.Fd(), flag); err != nil {
		oldNS.Close()
		return nil, fmt.Errorf("error setting namespace of type %v and path %q: %v", ns.Type, ns.Path, err)
	}
	return func() {
		log.Infof("Restoring namespace %v", ns.Type)
		defer oldNS.Close()
		if err := setNS(oldNS.Fd(), flag); err != nil {
			panic(fmt.Sprintf("error restoring namespace: of type %v: %v", ns.Type, err))
		}
	}, nil
}

// StartInNS joins or creates the given namespaces and calls cmd.Start before
// restoring the namespaces to the original values.
func StartInNS(cmd *exec.Cmd, nss []specs.LinuxNamespace) error {
	// We are about to setup namespaces, which requires the os thread being
	// locked so that Go doesn't change the thread out from under us.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}

	for _, ns := range nss {
		if ns.Path == "" {
			// No path.  Just set a flag to create a new namespace.
			cmd.SysProcAttr.Cloneflags |= nsCloneFlag(ns.Type)
			continue
		}
		// Join the given namespace, and restore the current namespace
		// before exiting.
		restoreNS, err := ApplyNS(ns)
		if err != nil {
			return err
		}
		defer restoreNS()
	}

	return cmd.Start()
}

// SetUIDGIDMappings sets the given uid/gid mappings from the spec on the cmd.
func SetUIDGIDMappings(cmd *exec.Cmd, s *specs.Spec) {
	if s.Linux == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	for _, idMap := range s.Linux.UIDMappings {
		log.Infof("Mapping host uid %d to container uid %d (size=%d)", idMap.HostID, idMap.ContainerID, idMap.Size)
		cmd.SysProcAttr.UidMappings = append(cmd.SysProcAttr.UidMappings, syscall.SysProcIDMap{
			ContainerID: int(idMap.ContainerID),
			HostID:      int(idMap.HostID),
			Size:        int(idMap.Size),
		})
	}
	for _, idMap := range s.Linux.GIDMappings {
		log.Infof("Mapping host gid %d to container gid %d (size=%d)", idMap.HostID, idMap.ContainerID, idMap.Size)
		cmd.SysProcAttr.GidMappings = append(cmd.SysProcAttr.GidMappings, syscall.SysProcIDMap{
			ContainerID: int(idMap.ContainerID),
			HostID:      int(idMap.HostID),
			Size:        int(idMap.Size),
		})
	}
}

// HasCapabilities returns true if the user has all capabilities in 'cs'.
func HasCapabilities(cs ...capability.Cap) bool {
	caps, err := capability.NewPid2(os.Getpid())
	if err != nil {
		return false
	}
	if err := caps.Load(); err != nil {
		return false
	}
	for _, c := range cs {
		if !caps.Get(capability.EFFECTIVE, c) {
			return false
		}
	}
	return true
}

// MaybeRunAsRoot ensures the process runs with capabilities needed to create a
// sandbox, e.g. CAP_SYS_ADMIN, CAP_SYS_CHROOT, etc. If capabilities are needed,
// it will create a new user namespace and re-execute the process as root
// inside the namespace with the same arguments and environment.
//
// This function returns immediately when no new capability is needed. If
// another process is executed, it returns straight from here with the same exit
// code as the child.
func MaybeRunAsRoot() error {
	if HasCapabilities(capability.CAP_SYS_ADMIN, capability.CAP_SYS_CHROOT, capability.CAP_SETUID, capability.CAP_SETGID) {
		return nil
	}

	// Current process doesn't have required capabilities, create user namespace
	// and run as root inside the namespace to acquire capabilities.
	log.Infof("*** Re-running as root in new user namespace ***")

	cmd := exec.Command("/proc/self/exe", os.Args[1:]...)

	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS,
		// Set current user/group as root inside the namespace. Since we may not
		// have CAP_SETUID/CAP_SETGID, just map root to the current user/group.
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		Credential:                 &syscall.Credential{Uid: 0, Gid: 0},
		GidMappingsEnableSetgroups: false,

		// Make sure child is killed when the parent terminates.
		Pdeathsig: syscall.SIGKILL,
	}

	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("re-executing self: %w", err)
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch)
	go func() {
		for {
			// Forward all signals to child process.
			cmd.Process.Signal(<-ch)
		}
	}()
	if err := cmd.Wait(); err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			if ws, ok := exit.Sys().(syscall.WaitStatus); ok {
				os.Exit(ws.ExitStatus())
			}
			log.Warningf("No wait status provided, exiting with -1: %v", err)
			os.Exit(-1)
		}
		return err
	}
	// Child completed with success.
	os.Exit(0)
	panic("unreachable")
}
