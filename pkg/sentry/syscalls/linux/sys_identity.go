// Copyright 2018 Google LLC
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

package linux

import (
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel/auth"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

const (
	// As NGROUPS_MAX in include/uapi/linux/limits.h.
	maxNGroups = 65536
)

// Getuid implements the Linux syscall getuid.
func Getuid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	c := t.Credentials()
	ruid := c.RealKUID.In(c.UserNamespace).OrOverflow()
	return uintptr(ruid), nil, nil
}

// Geteuid implements the Linux syscall geteuid.
func Geteuid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	c := t.Credentials()
	euid := c.EffectiveKUID.In(c.UserNamespace).OrOverflow()
	return uintptr(euid), nil, nil
}

// Getresuid implements the Linux syscall getresuid.
func Getresuid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	ruidAddr := args[0].Pointer()
	euidAddr := args[1].Pointer()
	suidAddr := args[2].Pointer()
	c := t.Credentials()
	ruid := c.RealKUID.In(c.UserNamespace).OrOverflow()
	euid := c.EffectiveKUID.In(c.UserNamespace).OrOverflow()
	suid := c.SavedKUID.In(c.UserNamespace).OrOverflow()
	if _, err := t.CopyOut(ruidAddr, ruid); err != nil {
		return 0, nil, err
	}
	if _, err := t.CopyOut(euidAddr, euid); err != nil {
		return 0, nil, err
	}
	if _, err := t.CopyOut(suidAddr, suid); err != nil {
		return 0, nil, err
	}
	return 0, nil, nil
}

// Getgid implements the Linux syscall getgid.
func Getgid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	c := t.Credentials()
	rgid := c.RealKGID.In(c.UserNamespace).OrOverflow()
	return uintptr(rgid), nil, nil
}

// Getegid implements the Linux syscall getegid.
func Getegid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	c := t.Credentials()
	egid := c.EffectiveKGID.In(c.UserNamespace).OrOverflow()
	return uintptr(egid), nil, nil
}

// Getresgid implements the Linux syscall getresgid.
func Getresgid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rgidAddr := args[0].Pointer()
	egidAddr := args[1].Pointer()
	sgidAddr := args[2].Pointer()
	c := t.Credentials()
	rgid := c.RealKGID.In(c.UserNamespace).OrOverflow()
	egid := c.EffectiveKGID.In(c.UserNamespace).OrOverflow()
	sgid := c.SavedKGID.In(c.UserNamespace).OrOverflow()
	if _, err := t.CopyOut(rgidAddr, rgid); err != nil {
		return 0, nil, err
	}
	if _, err := t.CopyOut(egidAddr, egid); err != nil {
		return 0, nil, err
	}
	if _, err := t.CopyOut(sgidAddr, sgid); err != nil {
		return 0, nil, err
	}
	return 0, nil, nil
}

// Setuid implements the Linux syscall setuid.
func Setuid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	uid := auth.UID(args[0].Int())
	return 0, nil, t.SetUID(uid)
}

// Setreuid implements the Linux syscall setreuid.
func Setreuid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	ruid := auth.UID(args[0].Int())
	euid := auth.UID(args[1].Int())
	return 0, nil, t.SetREUID(ruid, euid)
}

// Setresuid implements the Linux syscall setreuid.
func Setresuid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	ruid := auth.UID(args[0].Int())
	euid := auth.UID(args[1].Int())
	suid := auth.UID(args[2].Int())
	return 0, nil, t.SetRESUID(ruid, euid, suid)
}

// Setgid implements the Linux syscall setgid.
func Setgid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	gid := auth.GID(args[0].Int())
	return 0, nil, t.SetGID(gid)
}

// Setregid implements the Linux syscall setregid.
func Setregid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rgid := auth.GID(args[0].Int())
	egid := auth.GID(args[1].Int())
	return 0, nil, t.SetREGID(rgid, egid)
}

// Setresgid implements the Linux syscall setregid.
func Setresgid(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	rgid := auth.GID(args[0].Int())
	egid := auth.GID(args[1].Int())
	sgid := auth.GID(args[2].Int())
	return 0, nil, t.SetRESGID(rgid, egid, sgid)
}

// Getgroups implements the Linux syscall getgroups.
func Getgroups(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	size := int(args[0].Int())
	if size < 0 {
		return 0, nil, syserror.EINVAL
	}
	kgids := t.Credentials().ExtraKGIDs
	// "If size is zero, list is not modified, but the total number of
	// supplementary group IDs for the process is returned." - getgroups(2)
	if size == 0 {
		return uintptr(len(kgids)), nil, nil
	}
	if size < len(kgids) {
		return 0, nil, syserror.EINVAL
	}
	gids := make([]auth.GID, len(kgids))
	for i, kgid := range kgids {
		gids[i] = kgid.In(t.UserNamespace()).OrOverflow()
	}
	if _, err := t.CopyOut(args[1].Pointer(), gids); err != nil {
		return 0, nil, err
	}
	return uintptr(len(gids)), nil, nil
}

// Setgroups implements the Linux syscall setgroups.
func Setgroups(t *kernel.Task, args arch.SyscallArguments) (uintptr, *kernel.SyscallControl, error) {
	size := args[0].Int()
	if size < 0 || size > maxNGroups {
		return 0, nil, syserror.EINVAL
	}
	if size == 0 {
		return 0, nil, t.SetExtraGIDs(nil)
	}
	gids := make([]auth.GID, size)
	if _, err := t.CopyIn(args[1].Pointer(), &gids); err != nil {
		return 0, nil, err
	}
	return 0, nil, t.SetExtraGIDs(gids)
}
