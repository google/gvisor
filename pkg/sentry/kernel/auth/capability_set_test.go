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

// capsEquals returns true when the given creds' capabilities match the given caps.
func capsEquals(creds *Credentials, caps TaskCapabilities) bool {
	return creds.PermittedCaps == caps.PermittedCaps &&
		creds.InheritableCaps == caps.InheritableCaps &&
		creds.EffectiveCaps == caps.EffectiveCaps &&
		creds.BoundingCaps == caps.BoundingCaps
}

// credentialsWithCaps returns a copy of creds with the given capabilities.
func credentialsWithCaps(creds *Credentials, permittedCaps, inheritableCaps, effectiveCaps, boundingCaps CapabilitySet) *Credentials {
	newCreds := creds.Fork()
	newCreds.PermittedCaps = permittedCaps
	newCreds.InheritableCaps = inheritableCaps
	newCreds.EffectiveCaps = effectiveCaps
	newCreds.BoundingCaps = boundingCaps
	return newCreds
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

func TestCapsFromVfsCaps(t *testing.T) {
	for _, tst := range []struct {
		name     string
		capData  linux.VfsNsCapData
		creds    *Credentials
		wantCaps TaskCapabilities
		wantErr  error
	}{
		{
			name: "TestRootCredential",
			capData: vfsCapDataFrom(
				true,                                  // effective
				CapabilitySetOf(linux.CAP_NET_ADMIN),  // permitted
				CapabilitySetOf(linux.CAP_NET_ADMIN)), // inheritable
			creds: credentialsWithCaps(
				NewRootCredentials(NewRootUserNamespace()),
				AllCapabilities,
				CapabilitySetOf(linux.CAP_NET_RAW),
				AllCapabilities,
				CapabilitySetOf(linux.CAP_SYSLOG)),
			wantCaps: TaskCapabilities{
				PermittedCaps:   AllCapabilities,
				InheritableCaps: CapabilitySetOf(linux.CAP_NET_RAW),
				EffectiveCaps:   AllCapabilities,
				BoundingCaps:    CapabilitySetOf(linux.CAP_SYSLOG),
			},
		},
		{
			name: "TestPermittedAndInheritableCaps",
			capData: vfsCapDataFrom(
				true, // effective
				CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETUID}),  // permitted
				CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETGID})), // inheritable
			creds: credentialsWithCaps(
				NewUserCredentials(123, 321, nil, nil, NewRootUserNamespace()),
				AllCapabilities,
				AllCapabilities,
				AllCapabilities,
				AllCapabilities),
			wantCaps: TaskCapabilities{
				PermittedCaps:   CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETUID, linux.CAP_SETGID}),
				InheritableCaps: AllCapabilities,
				EffectiveCaps:   CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETUID, linux.CAP_SETGID}),
				BoundingCaps:    AllCapabilities,
			},
		},
		{
			name: "TestEffectiveBitOff",
			capData: vfsCapDataFrom(
				false, // effective
				CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETUID}),  // permitted
				CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETGID})), // inheritable
			creds: credentialsWithCaps(
				NewUserCredentials(123, 321, nil, nil, NewRootUserNamespace()),
				AllCapabilities,
				AllCapabilities,
				AllCapabilities,
				AllCapabilities),
			wantCaps: TaskCapabilities{
				PermittedCaps:   CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETUID, linux.CAP_SETGID}),
				InheritableCaps: AllCapabilities,
				EffectiveCaps:   0,
				BoundingCaps:    AllCapabilities,
			},
		},
		{
			name: "TestInsufficientCaps",
			capData: vfsCapDataFrom(
				true, // effective
				CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETUID}), // permitted
				CapabilitySetOf(linux.CAP_CHOWN)),                                          // inheritable
			creds: credentialsWithCaps(
				NewUserCredentials(123, 321, nil, nil, NewRootUserNamespace()),
				AllCapabilities,
				AllCapabilities,
				AllCapabilities,
				CapabilitySetOf(linux.CAP_CHOWN)),
			wantErr: linuxerr.EPERM,
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			newCreds, err := CapsFromVfsCaps(tst.capData, tst.creds)
			if err == nil {
				if tst.wantErr != nil {
					t.Errorf("CapsFromVfsCaps(%v, %v) returned unexpected error %v", tst.capData, tst.creds, tst.wantErr)
				}
				if !capsEquals(newCreds, tst.wantCaps) {
					t.Errorf("CapsFromVfsCaps(%v, %v) returned capabilities: %v, want capabilities: %v",
						tst.capData, tst.creds,
						TaskCapabilities{
							PermittedCaps:   newCreds.PermittedCaps,
							InheritableCaps: newCreds.InheritableCaps,
							EffectiveCaps:   newCreds.EffectiveCaps,
							BoundingCaps:    newCreds.BoundingCaps,
						}, tst.wantCaps)
				}
			} else if tst.wantErr == nil || tst.wantErr.Error() != err.Error() {
				t.Errorf("CapsFromVfsCaps(%v, %v) returned error %v, wantErr: %v", tst.capData, tst.creds, err, tst.wantErr)
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
