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

package auth

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

// credentialsWithCaps creates a credentials object with the given capabilities.
func credentialsWithCaps(inheritable, bounding CapabilitySet) *Credentials {
	return NewUserCredentials(1001, 1001, nil, &TaskCapabilities{
		InheritableCaps: inheritable,
		BoundingCaps:    bounding,
	}, NewRootUserNamespace())
}

func vfsNsCapDataFrom(effective bool, rootid uint32, permitted, inheritable CapabilitySet) linux.VfsNsCapData {
	capData := vfsCapDataFrom(effective, permitted, inheritable)
	capData.MagicEtc = linux.VFS_CAP_REVISION_3
	if effective {
		capData.MagicEtc |= linux.VFS_CAP_FLAGS_EFFECTIVE
	}
	capData.RootID = rootid
	return capData
}

func vfsCapDataFrom(effective bool, permitted, inheritable CapabilitySet) linux.VfsNsCapData {
	var capData linux.VfsNsCapData
	capData.MagicEtc = linux.VFS_CAP_REVISION_2
	if effective {
		capData.MagicEtc |= linux.VFS_CAP_FLAGS_EFFECTIVE
	}
	capData.PermittedLo = uint32(permitted & 0xffffffff)
	capData.PermittedHi = uint32(permitted >> 32)
	capData.InheritableLo = uint32(inheritable & 0xffffffff)
	capData.InheritableHi = uint32(inheritable >> 32)
	return capData
}

func TestComputeCredsForExec(t *testing.T) {
	for _, tst := range []struct {
		name          string
		filePrivs     FilePrivileges
		creds         *Credentials
		noNewPrivs    bool
		stopPrivGain  bool
		allowSUID     bool
		wantPermitted CapabilitySet
		wantEffective bool
		wantErr       error
	}{
		{
			name: "TestSamePermittedAndInheritableCaps",
			filePrivs: FilePrivileges{
				HasCaps:         true,
				Effective:       true,
				PermittedCaps:   CapabilitySetOf(linux.CAP_NET_ADMIN),
				InheritableCaps: CapabilitySetOf(linux.CAP_NET_ADMIN),
			},
			creds:         credentialsWithCaps(AllCapabilities, AllCapabilities),
			wantPermitted: CapabilitySetOf(linux.CAP_NET_ADMIN),
			wantEffective: true,
		},
		{
			name: "TestDifferentPermittedAndInheritableCaps",
			filePrivs: FilePrivileges{
				HasCaps:         true,
				Effective:       true,
				PermittedCaps:   CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETUID}),
				InheritableCaps: CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETGID}),
			},
			creds:         credentialsWithCaps(AllCapabilities, AllCapabilities),
			wantPermitted: CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETUID, linux.CAP_SETGID}),
			wantEffective: true,
		},
		{
			name: "TestEffectiveBitOff",
			filePrivs: FilePrivileges{
				HasCaps:         true,
				Effective:       false,
				PermittedCaps:   CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETUID}),
				InheritableCaps: CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETGID}),
			},
			creds:         credentialsWithCaps(AllCapabilities, AllCapabilities),
			wantPermitted: CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETUID, linux.CAP_SETGID}),
			wantEffective: false,
		},
		{
			name: "TestInsufficientCaps",
			filePrivs: FilePrivileges{
				HasCaps:         true,
				Effective:       true,
				PermittedCaps:   CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETUID}),
				InheritableCaps: CapabilitySetOf(linux.CAP_CHOWN),
			},
			creds:   credentialsWithCaps(AllCapabilities, CapabilitySetOf(linux.CAP_CHOWN)),
			wantErr: linuxerr.EPERM,
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			newC, _, err := ComputeCredsForExec(tst.creds, tst.filePrivs, "", tst.noNewPrivs, tst.stopPrivGain, tst.allowSUID)
			if err == nil {
				if tst.wantErr != nil {
					t.Errorf("ComputeCredsForExec(%v) returned unexpected error %v", tst.filePrivs, tst.wantErr)
				}
				if newC.PermittedCaps != tst.wantPermitted {
					t.Errorf("ComputeCredsForExec(%v) set PermittedCaps to: %#x, want capabilities: %#x",
						tst.filePrivs, newC.PermittedCaps, tst.wantPermitted)
				}
				if tst.wantEffective && newC.EffectiveCaps != newC.PermittedCaps {
					t.Errorf("ComputeCredsForExec(%v) did not set effective caps", tst.filePrivs)
				}
				if !tst.wantEffective && newC.EffectiveCaps != CapabilitySet(0) {
					t.Errorf("ComputeCredsForExec(%v) did not clear effective caps: %#x",
						tst.filePrivs, newC.EffectiveCaps)
				}
			} else if tst.wantErr == nil || tst.wantErr.Error() != err.Error() {
				t.Errorf("ComputeCredsForExec(%v) returned error %v, wantErr: %v", tst.filePrivs, err, tst.wantErr)
			}
		})
	}
}

func TestVfsCapData(t *testing.T) {
	for _, tst := range []struct {
		name    string
		data    []byte
		capData linux.VfsNsCapData
		wantErr error
	}{
		{
			name:    "VfsCapRevision1",
			data:    []byte{0, 0, 0, 1, 0, 16, 0, 0, 0, 0, 0, 0},
			wantErr: linuxerr.EINVAL,
		},
		{
			name:    "VfsCapRevision2WithEffective",
			data:    []byte{1, 0, 0, 2, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0},
			capData: vfsCapDataFrom(true, CapabilitySetOf(linux.CAP_NET_RAW), CapabilitySetOf(linux.CAP_SYSLOG)),
		},
		{
			name:    "VfsCapRevision3",
			data:    []byte{0, 0, 0, 3, 0, 0, 0, 0, 0, 16, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0},
			capData: vfsNsCapDataFrom(false, 1, CapabilitySetOf(linux.CAP_SYSLOG), CapabilitySetOf(linux.CAP_NET_ADMIN)),
		},
		{
			name:    "VfsCapRevisionNotSupported",
			data:    []byte{0, 0, 0, 0xf, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0},
			wantErr: linuxerr.EINVAL,
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			capData, err := VfsCapDataOf(tst.data)
			if err == nil {
				if tst.wantErr != nil {
					t.Errorf("VfsCapDataOf(%v) returned unexpected error %v", tst.data, tst.wantErr)
				}
				if tst.capData != capData {
					t.Errorf("VfsCapDataOf(%v) = %+v, want %+v", tst.data, capData, tst.capData)
				}
			} else if tst.wantErr == nil || tst.wantErr.Error() != err.Error() {
				t.Errorf("VfsCapDataOf(%v) returned error %v, wantErr: %v", tst.data, err, tst.wantErr)
			}
		})
	}
}

func TestXattrCapsSizeBytes(t *testing.T) {
	if got := (*linux.VfsCapData)(nil).SizeBytes(); got != linux.XATTR_CAPS_SZ_2 {
		t.Errorf("XATTR_CAPS_SZ_2 = %v, got %v", linux.XATTR_CAPS_SZ_2, got)
	}
	if got := (*linux.VfsNsCapData)(nil).SizeBytes(); got != linux.XATTR_CAPS_SZ_3 {
		t.Errorf("XATTR_CAPS_SZ_3 = %v, got %v", linux.XATTR_CAPS_SZ_3, got)
	}
}
