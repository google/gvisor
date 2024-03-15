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
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
)

// capsEquals returns trun when the given creds' capabilities match the given caps.
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

func TestCapsFromVfsCaps(t *testing.T) {
	for _, tst := range []struct {
		name     string
		capData  VfsCapData
		creds    *Credentials
		wantCaps TaskCapabilities
		wantErr  error
	}{
		{
			name: "TestRootCredential",
			capData: VfsCapData{
				MagicEtc:    0x2000001,
				Permitted:   CapabilitySetOf(linux.CAP_NET_ADMIN),
				Inheritable: CapabilitySetOf(linux.CAP_NET_ADMIN),
			},
			creds: credentialsWithCaps(NewRootCredentials(NewRootUserNamespace()), AllCapabilities, CapabilitySetOf(linux.CAP_NET_RAW), AllCapabilities, CapabilitySetOf(linux.CAP_SYSLOG)),
			wantCaps: TaskCapabilities{
				PermittedCaps:   AllCapabilities,
				InheritableCaps: CapabilitySetOf(linux.CAP_NET_RAW),
				EffectiveCaps:   AllCapabilities,
				BoundingCaps:    CapabilitySetOf(linux.CAP_SYSLOG),
			},
			wantErr: nil,
		},
		{
			name: "TestPermittedAndInheritableCaps",
			capData: VfsCapData{
				MagicEtc:    0x2000001,
				Permitted:   CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETUID}),
				Inheritable: CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETGID}),
			},
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
			wantErr: nil,
		},
		{
			name: "TestEffectiveBitOff",
			capData: VfsCapData{
				MagicEtc:    0x2000000,
				Permitted:   CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETUID}),
				Inheritable: CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETGID}),
			},
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
			wantErr: nil,
		},
		{
			name: "TestInsufficientCaps",
			capData: VfsCapData{
				MagicEtc:    0x2000001,
				Permitted:   CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN, linux.CAP_SETUID}),
				Inheritable: CapabilitySetOfMany([]linux.Capability{linux.CAP_CHOWN}),
			},
			creds: credentialsWithCaps(
				NewUserCredentials(123, 321, nil, nil, NewRootUserNamespace()),
				AllCapabilities,
				AllCapabilities,
				AllCapabilities,
				CapabilitySetOf(linux.CAP_CHOWN)),
			wantCaps: TaskCapabilities{},
			wantErr:  linuxerr.EPERM,
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
		capData VfsCapData
		wantErr error
	}{
		{
			name:    "VfsCapRevision1",
			data:    []byte{0, 0, 0, 1, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			capData: VfsCapData{},
			wantErr: fmt.Errorf("VFS_CAP_REVISION_%v with cap data size %v is not supported", 0x1000000, 20),
		},
		{
			name: "VfsCapRevision2",
			data: []byte{1, 0, 0, 2, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0},
			capData: VfsCapData{
				MagicEtc:    0x2000001,
				Permitted:   CapabilitySetOf(linux.CAP_NET_RAW),
				Inheritable: CapabilitySetOf(linux.CAP_SYSLOG),
			},
			wantErr: nil,
		},
		{
			name: "VfsCapRevision3",
			data: []byte{0, 0, 0, 3, 0, 0, 0, 0, 0, 16, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0},
			capData: VfsCapData{
				MagicEtc:    0x3000000,
				RootID:      1,
				Permitted:   CapabilitySetOf(linux.CAP_SYSLOG),
				Inheritable: CapabilitySetOf(linux.CAP_NET_ADMIN),
			},
			wantErr: nil,
		},
		{
			name:    "VfsCapRevisionNotSupported",
			data:    []byte{0, 0, 0, 0xf, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0},
			capData: VfsCapData{},
			wantErr: fmt.Errorf("VFS_CAP_REVISION_%v with cap data size %v is not supported", 0xf000000, 20),
		},
		{
			name:    "VfsInvalidInput",
			data:    []byte{0, 0, 0, 0},
			capData: VfsCapData{},
			wantErr: fmt.Errorf("the size of security.capability is too small, actual size: %v", 4),
		},
	} {
		t.Run(tst.name, func(t *testing.T) {
			capData, err := VfsCapDataOf(tst.data)
			if err == nil {
				if tst.wantErr != nil {
					t.Errorf("VfsCapDataOf(%v) returned unexpected error %v", tst.data, tst.wantErr)
				}
				if tst.capData != capData {
					t.Errorf("VfsCapDataOf(%v) = %v, want %v", tst.data, capData, tst.capData)
				}
			} else if tst.wantErr == nil || tst.wantErr.Error() != err.Error() {
				t.Errorf("VfsCapDataOf(%v) returned error %v, wantErr: %v", tst.data, err, tst.wantErr)
			}
		})
	}
}
