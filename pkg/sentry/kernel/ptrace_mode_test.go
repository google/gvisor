// Copyright 2026 The gVisor Authors.
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

package kernel

import (
	"fmt"
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
)

// testCreds returns a set of credentials with the given user and group IDs in
// ns and no capabilities.
func testCreds(ns *auth.UserNamespace, uid auth.KUID, gid auth.KGID) *auth.Credentials {
	creds := auth.NewRootCredentials(ns).Fork()
	creds.RealKUID, creds.EffectiveKUID, creds.SavedKUID = uid, uid, uid
	creds.RealKGID, creds.EffectiveKGID, creds.SavedKGID = gid, gid, gid
	creds.PermittedCaps = 0
	creds.EffectiveCaps = 0
	return creds
}

func TestCanTraceCredsModeValidation(t *testing.T) {
	rootNS := auth.NewRootUserNamespace()
	caller := testCreds(rootNS, auth.KUID(1000), auth.KGID(1000))
	target := testCreds(rootNS, auth.KUID(1000), auth.KGID(1000))
	for _, test := range []struct {
		name string
		mode PtraceAccessMode
		want bool
	}{
		{name: "zero", mode: 0, want: false},
		{name: "read only", mode: PtraceAccessModeRead, want: false},
		{name: "attach only", mode: PtraceAccessModeAttach, want: false},
		{name: "both creds modes", mode: PtraceAccessModeFsCreds | PtraceAccessModeRealCreds, want: false},
		{name: "all flags", mode: PtraceAccessModeRead | PtraceAccessModeAttach | PtraceAccessModeFsCreds | PtraceAccessModeRealCreds, want: false},
		{name: "read realcreds", mode: PtraceAccessModeRead | PtraceAccessModeRealCreds, want: true},
		{name: "attach realcreds", mode: PtraceAccessModeAttach | PtraceAccessModeRealCreds, want: true},
		{name: "read fscreds", mode: PtraceAccessModeRead | PtraceAccessModeFsCreds, want: true},
		{name: "attach fscreds", mode: PtraceAccessModeAttach | PtraceAccessModeFsCreds, want: true},
		{name: "read realcreds noaudit", mode: PtraceAccessModeRead | PtraceAccessModeRealCreds | PtraceAccessModeNoAudit, want: true},
		{name: "read fscreds sched", mode: PtraceAccessModeRead | PtraceAccessModeFsCreds | PtraceAccessModeSched, want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := canTraceCreds(test.mode, caller, target); got != test.want {
				t.Errorf("canTraceCreds(%v, caller, target) = %t, want %t", test.mode, got, test.want)
			}
		})
	}
}

func TestCanTraceCredsSetuid(t *testing.T) {
	rootNS := auth.NewRootUserNamespace()
	// The caller is a setuid-root binary: it retains its real UID and GID of
	// 1000 while its effective UID and GID are root. The target is owned by
	// UID/GID 1000.
	caller := testCreds(rootNS, auth.KUID(1000), auth.KGID(1000))
	caller.EffectiveKUID = auth.RootKUID
	caller.EffectiveKGID = auth.RootKGID
	target := testCreds(rootNS, auth.KUID(1000), auth.KGID(1000))
	for _, test := range []struct {
		name string
		mode PtraceAccessMode
		want bool
	}{
		// PTRACE_MODE_REALCREDS uses the caller's real IDs, which match the
		// target, so access is granted.
		{name: "realcreds", mode: PtraceAccessModeRead | PtraceAccessModeRealCreds, want: true},
		// PTRACE_MODE_FSCREDS uses the caller's effective IDs, which do not
		// match the target, so access is denied.
		{name: "fscreds", mode: PtraceAccessModeRead | PtraceAccessModeFsCreds, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := canTraceCreds(test.mode, caller, target); got != test.want {
				t.Errorf("canTraceCreds(%v, caller, target) = %t, want %t", test.mode, got, test.want)
			}
		})
	}
}

func TestCanTraceCredsSetgid(t *testing.T) {
	rootNS := auth.NewRootUserNamespace()
	// The caller's real and effective UIDs match the target's, but its
	// effective GID is root while its real GID matches the target's.
	caller := testCreds(rootNS, auth.KUID(1000), auth.KGID(1000))
	caller.EffectiveKGID = auth.RootKGID
	target := testCreds(rootNS, auth.KUID(1000), auth.KGID(1000))
	for _, test := range []struct {
		name string
		mode PtraceAccessMode
		want bool
	}{
		{name: "realcreds", mode: PtraceAccessModeRead | PtraceAccessModeRealCreds, want: true},
		{name: "fscreds", mode: PtraceAccessModeRead | PtraceAccessModeFsCreds, want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := canTraceCreds(test.mode, caller, target); got != test.want {
				t.Errorf("canTraceCreds(%v, caller, target) = %t, want %t", test.mode, got, test.want)
			}
		})
	}
}

func TestCanTraceCredsCapabilitySuperset(t *testing.T) {
	rootNS := auth.NewRootUserNamespace()
	// The caller has CAP_SYS_ADMIN and CAP_KILL in its permitted set but only
	// CAP_KILL in its effective set (e.g. a setuid-root program that retains
	// permitted capabilities while dropping effective ones). It does not have
	// CAP_SYS_PTRACE anywhere.
	caller := testCreds(rootNS, auth.KUID(1000), auth.KGID(1000))
	caller.PermittedCaps = auth.CapabilitySetOfMany([]linux.Capability{linux.CAP_SYS_ADMIN, linux.CAP_KILL})
	caller.EffectiveCaps = auth.CapabilitySetOf(linux.CAP_KILL)
	for _, test := range []struct {
		name       string
		targetPerm auth.CapabilitySet
		mode       PtraceAccessMode
		want       bool
	}{
		{
			name:       "realcreds permitted superset",
			targetPerm: auth.CapabilitySetOf(linux.CAP_SYS_ADMIN),
			mode:       PtraceAccessModeRead | PtraceAccessModeRealCreds,
			want:       true,
		},
		{
			name:       "fscreds effective not superset",
			targetPerm: auth.CapabilitySetOf(linux.CAP_SYS_ADMIN),
			mode:       PtraceAccessModeRead | PtraceAccessModeFsCreds,
			want:       false,
		},
		{
			name:       "fscreds effective superset",
			targetPerm: auth.CapabilitySetOf(linux.CAP_KILL),
			mode:       PtraceAccessModeRead | PtraceAccessModeFsCreds,
			want:       true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			target := testCreds(rootNS, auth.KUID(1000), auth.KGID(1000))
			target.PermittedCaps = test.targetPerm
			if got := canTraceCreds(test.mode, caller, target); got != test.want {
				t.Errorf("canTraceCreds(%v, caller, target) = %t, want %t", test.mode, got, test.want)
			}
		})
	}
}

func TestCanTraceCredsUserNamespace(t *testing.T) {
	rootNS := auth.NewRootUserNamespace()
	childNS, err := auth.NewRootCredentials(rootNS).NewChildUserNamespace()
	if err != nil {
		t.Fatalf("NewChildUserNamespace: %v", err)
	}
	for _, test := range []struct {
		name   string
		caller *auth.Credentials
		target *auth.Credentials
		want   bool
	}{
		{
			// The caller lives in a child user namespace with a full
			// capability set there, but does not have CAP_SYS_PTRACE in the
			// root user namespace. Even though its permitted capabilities are
			// a superset of the target's, the commoncap check requires that
			// both processes be in the same user namespace.
			name:   "caller in child namespace",
			caller: testCreds(childNS, auth.KUID(1000), auth.KGID(1000)),
			target: testCreds(rootNS, auth.KUID(1000), auth.KGID(1000)),
			want:   false,
		},
		{
			// The caller and target are in the same child user namespace; the
			// caller's permitted capabilities are a superset of the target's,
			// so access is granted.
			name:   "caller and target in child namespace",
			caller: testCreds(childNS, auth.KUID(1000), auth.KGID(1000)),
			target: testCreds(childNS, auth.KUID(1000), auth.KGID(1000)),
			want:   true,
		},
	} {
		// Grant the caller capabilities so that the check under test is the
		// user namespace comparison rather than the capability superset
		// check.
		caller := test.caller
		caller.PermittedCaps = auth.CapabilitySetOfMany([]linux.Capability{linux.CAP_DAC_OVERRIDE, linux.CAP_KILL})
		caller.EffectiveCaps = auth.CapabilitySetOf(linux.CAP_KILL)
		target := test.target
		target.PermittedCaps = auth.CapabilitySetOf(linux.CAP_KILL)
		for _, mode := range []PtraceAccessMode{
			PtraceAccessModeRead | PtraceAccessModeRealCreds,
			PtraceAccessModeRead | PtraceAccessModeFsCreds,
		} {
			t.Run(fmt.Sprintf("%s mode=%v", test.name, mode), func(t *testing.T) {
				if got := canTraceCreds(mode, caller, target); got != test.want {
					t.Errorf("canTraceCreds(%v, caller, target) = %t, want %t", mode, got, test.want)
				}
			})
		}
	}
}

func TestCanTraceCredsCapSysPtrace(t *testing.T) {
	rootNS := auth.NewRootUserNamespace()
	// The caller is root in the root user namespace with all capabilities, so
	// CAP_SYS_PTRACE grants access despite the mismatched UIDs.
	caller := auth.NewRootCredentials(rootNS)
	target := testCreds(rootNS, auth.KUID(1000), auth.KGID(1000))
	for _, mode := range []PtraceAccessMode{
		PtraceAccessModeRead | PtraceAccessModeRealCreds,
		PtraceAccessModeRead | PtraceAccessModeFsCreds,
	} {
		if got := canTraceCreds(mode, caller, target); !got {
			t.Errorf("canTraceCreds(%v, root caller, uid 1000 target) = false, want true", mode)
		}
	}
}
