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

package cmd

import (
	"fmt"
	"os"

	specs "github.com/opencontainers/runtime-spec/specs-go"
	"github.com/syndtr/gocapability/capability"
	"gvisor.googlesource.com/gvisor/pkg/log"
)

// applyCaps applies the capabilities in the spec to the current thread.
//
// Note that it must be called with current thread locked.
func applyCaps(caps *specs.LinuxCapabilities) error {
	setter, err := capability.NewPid2(os.Getpid())
	if err != nil {
		return err
	}
	if err := setter.Load(); err != nil {
		return err
	}

	bounding, err := trimCaps(caps.Bounding, setter)
	if err != nil {
		return err
	}
	setter.Set(capability.BOUNDS, bounding...)

	effective, err := trimCaps(caps.Effective, setter)
	if err != nil {
		return err
	}
	setter.Set(capability.EFFECTIVE, effective...)

	permitted, err := trimCaps(caps.Permitted, setter)
	if err != nil {
		return err
	}
	setter.Set(capability.PERMITTED, permitted...)

	inheritable, err := trimCaps(caps.Inheritable, setter)
	if err != nil {
		return err
	}
	setter.Set(capability.INHERITABLE, inheritable...)

	ambient, err := trimCaps(caps.Ambient, setter)
	if err != nil {
		return err
	}
	setter.Set(capability.AMBIENT, ambient...)

	return setter.Apply(capability.CAPS | capability.BOUNDS | capability.AMBS)
}

func trimCaps(names []string, setter capability.Capabilities) ([]capability.Cap, error) {
	wantedCaps, err := capsFromNames(names)
	if err != nil {
		return nil, err
	}

	// Trim down capabilities that aren't possible to acquire.
	var caps []capability.Cap
	for _, c := range wantedCaps {
		// Capability rules are more complicated than this, but this catches most
		// problems with tests running with non-privileged user.
		if setter.Get(capability.PERMITTED, c) {
			caps = append(caps, c)
		} else {
			log.Warningf("Capability %q is not permitted, dropping it.", c)
		}
	}
	return caps, nil
}

func capsFromNames(names []string) ([]capability.Cap, error) {
	var caps []capability.Cap
	for _, name := range names {
		cap, ok := capFromName[name]
		if !ok {
			return nil, fmt.Errorf("invalid capability %q", name)
		}
		caps = append(caps, cap)
	}
	return caps, nil
}

var capFromName = map[string]capability.Cap{
	"CAP_CHOWN":            capability.CAP_CHOWN,
	"CAP_DAC_OVERRIDE":     capability.CAP_DAC_OVERRIDE,
	"CAP_DAC_READ_SEARCH":  capability.CAP_DAC_READ_SEARCH,
	"CAP_FOWNER":           capability.CAP_FOWNER,
	"CAP_FSETID":           capability.CAP_FSETID,
	"CAP_KILL":             capability.CAP_KILL,
	"CAP_SETGID":           capability.CAP_SETGID,
	"CAP_SETUID":           capability.CAP_SETUID,
	"CAP_SETPCAP":          capability.CAP_SETPCAP,
	"CAP_LINUX_IMMUTABLE":  capability.CAP_LINUX_IMMUTABLE,
	"CAP_NET_BIND_SERVICE": capability.CAP_NET_BIND_SERVICE,
	"CAP_NET_BROADCAST":    capability.CAP_NET_BROADCAST,
	"CAP_NET_ADMIN":        capability.CAP_NET_ADMIN,
	"CAP_NET_RAW":          capability.CAP_NET_RAW,
	"CAP_IPC_LOCK":         capability.CAP_IPC_LOCK,
	"CAP_IPC_OWNER":        capability.CAP_IPC_OWNER,
	"CAP_SYS_MODULE":       capability.CAP_SYS_MODULE,
	"CAP_SYS_RAWIO":        capability.CAP_SYS_RAWIO,
	"CAP_SYS_CHROOT":       capability.CAP_SYS_CHROOT,
	"CAP_SYS_PTRACE":       capability.CAP_SYS_PTRACE,
	"CAP_SYS_PACCT":        capability.CAP_SYS_PACCT,
	"CAP_SYS_ADMIN":        capability.CAP_SYS_ADMIN,
	"CAP_SYS_BOOT":         capability.CAP_SYS_BOOT,
	"CAP_SYS_NICE":         capability.CAP_SYS_NICE,
	"CAP_SYS_RESOURCE":     capability.CAP_SYS_RESOURCE,
	"CAP_SYS_TIME":         capability.CAP_SYS_TIME,
	"CAP_SYS_TTY_CONFIG":   capability.CAP_SYS_TTY_CONFIG,
	"CAP_MKNOD":            capability.CAP_MKNOD,
	"CAP_LEASE":            capability.CAP_LEASE,
	"CAP_AUDIT_WRITE":      capability.CAP_AUDIT_WRITE,
	"CAP_AUDIT_CONTROL":    capability.CAP_AUDIT_CONTROL,
	"CAP_SETFCAP":          capability.CAP_SETFCAP,
	"CAP_MAC_OVERRIDE":     capability.CAP_MAC_OVERRIDE,
	"CAP_MAC_ADMIN":        capability.CAP_MAC_ADMIN,
	"CAP_SYSLOG":           capability.CAP_SYSLOG,
	"CAP_WAKE_ALARM":       capability.CAP_WAKE_ALARM,
	"CAP_BLOCK_SUSPEND":    capability.CAP_BLOCK_SUSPEND,
	"CAP_AUDIT_READ":       capability.CAP_AUDIT_READ,
}
