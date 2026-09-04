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

package kernel

import (
	"testing"

	"gvisor.dev/gvisor/pkg/abi/linux"
)

// TestInitSignalDiscarded verifies the discard rule that keeps a PID namespace's
// init process alive under Linux SIGNAL_UNKILLABLE semantics
// (kernel/signal.c:sig_task_ignored(), pid_namespaces(7)).
func TestInitSignalDiscarded(t *testing.T) {
	dflAct := linux.SigAction{Handler: linux.SIG_DFL}
	ignAct := linux.SigAction{Handler: linux.SIG_IGN}
	handlerAct := linux.SigAction{Handler: 0x1000} // arbitrary user handler

	for _, tc := range []struct {
		name   string
		sig    linux.Signal
		act    linux.SigAction
		forced bool
		want   bool
	}{
		// In-sandbox (forced == false): SIGNAL_UNKILLABLE semantics.
		// SIGKILL/SIGSTOP and default-fatal signals with no handler are
		// discarded, but an installed handler receives the signal.
		{"sigkill from peer", linux.SIGKILL, dflAct, false, true},
		{"sigstop from peer", linux.SIGSTOP, dflAct, false, true},
		{"sigterm default peer", linux.SIGTERM, dflAct, false, true},
		{"sigtstp default peer (stop)", linux.SIGTSTP, dflAct, false, true},
		{"sigterm handler peer", linux.SIGTERM, handlerAct, false, false},
		{"sigquit handler peer (core)", linux.SIGQUIT, handlerAct, false, false},
		{"sigterm ignored peer", linux.SIGTERM, ignAct, false, true},
		// Non-fatal-by-default signals are still always delivered.
		{"sigchld default peer", linux.SIGCHLD, dflAct, false, false},
		{"sigwinch handler peer", linux.SIGWINCH, handlerAct, false, false},

		// Out-of-sandbox (forced == true): Linux semantics.
		// SIGKILL/SIGSTOP are delivered so the control plane can tear the
		// sandbox down.
		{"sigkill forced", linux.SIGKILL, dflAct, true, false},
		{"sigstop forced", linux.SIGSTOP, dflAct, true, false},
		// Other fatal signals are force-delivered only to an installed handler;
		// with the default disposition they are discarded (Linux force-delivers
		// only sig_kernel_only signals).
		{"sigterm handler forced", linux.SIGTERM, handlerAct, true, false},
		{"sigterm default forced", linux.SIGTERM, dflAct, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := initSignalDiscarded(tc.sig, tc.act, tc.forced); got != tc.want {
				t.Errorf("initSignalDiscarded(%d, handler=%#x, forced=%t) = %t, want %t",
					tc.sig, tc.act.Handler, tc.forced, got, tc.want)
			}
		})
	}
}

// TestMaybeForceInitSignal verifies that external signals (SI_USER) targeted at
// the global init thread group are marked privileged (SI_KERNEL) when
// SIGNAL_UNKILLABLE protection is enabled, and left untouched otherwise.
func TestMaybeForceInitSignal(t *testing.T) {
	k := &Kernel{signalUnkillable: SignalUnkillableLinux}
	initTG := &ThreadGroup{}
	k.TestOnlySetGlobalInit(initTG)
	otherTG := &ThreadGroup{}

	userSig := &linux.SignalInfo{Signo: int32(linux.SIGTERM), Code: linux.SI_USER}
	kernelSig := &linux.SignalInfo{Signo: int32(linux.SIGTERM), Code: linux.SI_KERNEL}

	// 1. Target is globalInit and Code is SI_USER -> forced to SI_KERNEL.
	forced := k.maybeForceInitSignal(initTG, userSig)
	if forced.Code != linux.SI_KERNEL {
		t.Errorf("got Code %d, want SI_KERNEL", forced.Code)
	}
	if userSig.Code != linux.SI_USER {
		t.Errorf("original SignalInfo was mutated: got Code %d, want SI_USER", userSig.Code)
	}

	// 2. Target is NOT globalInit -> untouched.
	if got := k.maybeForceInitSignal(otherTG, userSig); got.Code != linux.SI_USER {
		t.Errorf("otherTG: got Code %d, want SI_USER", got.Code)
	}

	// 3. Signal is already SI_KERNEL -> untouched.
	if got := k.maybeForceInitSignal(initTG, kernelSig); got.Code != linux.SI_KERNEL {
		t.Errorf("kernelSig: got Code %d, want SI_KERNEL", got.Code)
	}

	// 4. Policy is None -> untouched.
	k.SetSignalUnkillablePolicy(SignalUnkillableNone)
	if got := k.maybeForceInitSignal(initTG, userSig); got.Code != linux.SI_USER {
		t.Errorf("policy None: got Code %d, want SI_USER", got.Code)
	}
}

// TestForcedSignalsToInit verifies that signals from outside the PID namespace
// (e.g. host/kernel or ancestor namespaces) are correctly classified as forced,
// and that forced signals are delivered to init while unforced peer signals are
// discarded under SIGNAL_UNKILLABLE semantics.
func TestForcedSignalsToInit(t *testing.T) {
	dflAct := linux.SigAction{Handler: linux.SIG_DFL}
	handlerAct := linux.SigAction{Handler: 0x1000}

	testCases := []struct {
		name       string
		info       *linux.SignalInfo
		wantForced bool
	}{
		{
			name:       "SI_KERNEL (host/kernel) is forced",
			info:       &linux.SignalInfo{Signo: int32(linux.SIGKILL), Code: linux.SI_KERNEL},
			wantForced: true,
		},
		{
			name: "SI_USER with PID 0 (ancestor namespace) is forced",
			info: func() *linux.SignalInfo {
				info := &linux.SignalInfo{Signo: int32(linux.SIGKILL), Code: linux.SI_USER}
				info.SetPID(0)
				return info
			}(),
			wantForced: true,
		},
		{
			name: "SI_TKILL with PID 0 (ancestor namespace) is forced",
			info: func() *linux.SignalInfo {
				info := &linux.SignalInfo{Signo: int32(linux.SIGKILL), Code: linux.SI_TKILL}
				info.SetPID(0)
				return info
			}(),
			wantForced: true,
		},
		{
			name: "SI_QUEUE with PID 0 (ancestor namespace) is forced",
			info: func() *linux.SignalInfo {
				info := &linux.SignalInfo{Signo: int32(linux.SIGKILL), Code: linux.SI_QUEUE}
				info.SetPID(0)
				return info
			}(),
			wantForced: true,
		},
		{
			name: "SI_USER with PID > 0 (peer in same namespace) is not forced",
			info: func() *linux.SignalInfo {
				info := &linux.SignalInfo{Signo: int32(linux.SIGKILL), Code: linux.SI_USER}
				info.SetPID(2)
				return info
			}(),
			wantForced: false,
		},
		{
			name: "SI_TKILL with PID > 0 (peer in same namespace) is not forced",
			info: func() *linux.SignalInfo {
				info := &linux.SignalInfo{Signo: int32(linux.SIGKILL), Code: linux.SI_TKILL}
				info.SetPID(2)
				return info
			}(),
			wantForced: false,
		},
		{
			name: "SI_QUEUE with PID > 0 (peer in same namespace) is not forced",
			info: func() *linux.SignalInfo {
				info := &linux.SignalInfo{Signo: int32(linux.SIGKILL), Code: linux.SI_QUEUE}
				info.SetPID(2)
				return info
			}(),
			wantForced: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			forced := isForcedSignal(tc.info)
			if forced != tc.wantForced {
				t.Fatalf("isForcedSignal(%+v) = %v, want %v", tc.info, forced, tc.wantForced)
			}

			sig := linux.Signal(tc.info.Signo)
			discarded := initSignalDiscarded(sig, dflAct, forced)
			// A forced SIGKILL must never be discarded; an unforced SIGKILL must be discarded.
			if tc.wantForced && discarded {
				t.Errorf("forced signal %v was unexpectedly discarded for init", sig)
			} else if !tc.wantForced && !discarded {
				t.Errorf("unforced signal %v was unexpectedly not discarded for init", sig)
			}
		})
	}

	// Forced SIGSTOP must be delivered (not discarded).
	kernelStop := &linux.SignalInfo{Signo: int32(linux.SIGSTOP), Code: linux.SI_KERNEL}
	if !isForcedSignal(kernelStop) {
		t.Fatal("kernelStop should be forced")
	}
	if initSignalDiscarded(linux.SIGSTOP, dflAct, isForcedSignal(kernelStop)) {
		t.Error("forced SIGSTOP was unexpectedly discarded for init")
	}

	// Forced default-fatal signals other than SIGKILL/SIGSTOP (such as SIGTERM)
	// are discarded when init has no handler, but delivered when a handler is installed.
	kernelTerm := &linux.SignalInfo{Signo: int32(linux.SIGTERM), Code: linux.SI_KERNEL}
	if !isForcedSignal(kernelTerm) {
		t.Fatal("kernelTerm should be forced")
	}
	if !initSignalDiscarded(linux.SIGTERM, dflAct, isForcedSignal(kernelTerm)) {
		t.Error("forced SIGTERM without handler should be discarded for init")
	}
	if initSignalDiscarded(linux.SIGTERM, handlerAct, isForcedSignal(kernelTerm)) {
		t.Error("forced SIGTERM with handler should be delivered to init")
	}
}

// TestDeliverSignalToInit verifies that sendSignalTimerLocked correctly applies
// initSignalDiscarded to discard unhandled signals to PID namespace init (PID 1)
// or permit delivery when appropriate.
func TestDeliverSignalToInit(t *testing.T) {
	initTG := &ThreadGroup{
		signalHandlers: NewSignalHandlers(),
	}
	initTG.pidWithinNS.Store(int32(initTID))

	nonInitTG := &ThreadGroup{
		signalHandlers: NewSignalHandlers(),
	}
	nonInitTG.pidWithinNS.Store(2)

	newTask := func(k *Kernel, tg *ThreadGroup) *Task {
		task := &Task{}
		task.k = k
		task.tg = tg
		prefix := ""
		task.logPrefix.Store(&prefix)
		// Block all signals so that if a signal is not discarded, canReceiveSignalLocked
		// returns false and does not attempt to interrupt the uninitialized task platform.
		task.signalMask.Store(^uint64(0))
		return task
	}

	peerKill := &linux.SignalInfo{Signo: int32(linux.SIGKILL), Code: linux.SI_USER}
	peerKill.SetPID(2)

	forcedKill := &linux.SignalInfo{Signo: int32(linux.SIGKILL), Code: linux.SI_KERNEL}

	peerTerm := &linux.SignalInfo{Signo: int32(linux.SIGTERM), Code: linux.SI_USER}
	peerTerm.SetPID(2)

	// 1. Under SignalUnkillableLinux, unforced peer SIGKILL to init is discarded.
	{
		k := &Kernel{signalUnkillable: SignalUnkillableLinux}
		task := newTask(k, initTG)
		if err := task.sendSignalTimerLocked(peerKill, false /* group */, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if task.pendingSignals.pendingSet.Load() != 0 {
			t.Errorf("peer SIGKILL was queued in pendingSignals, want discarded")
		}
	}

	// 2. Discarding with an IntervalTimer calls signalRejectedLocked on the timer.
	{
		k := &Kernel{signalUnkillable: SignalUnkillableLinux}
		task := newTask(k, initTG)
		timer := &IntervalTimer{}
		if err := task.sendSignalTimerLocked(peerKill, false /* group */, timer); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if timer.overrunCur != 1 {
			t.Errorf("expected timer.overrunCur == 1, got %d", timer.overrunCur)
		}
		if task.pendingSignals.pendingSet.Load() != 0 {
			t.Errorf("peer SIGKILL was queued in pendingSignals, want discarded")
		}
	}

	// 3. Peer unhandled SIGTERM to init is discarded.
	{
		k := &Kernel{signalUnkillable: SignalUnkillableLinux}
		task := newTask(k, initTG)
		if err := task.sendSignalTimerLocked(peerTerm, false /* group */, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if task.pendingSignals.pendingSet.Load() != 0 {
			t.Errorf("peer SIGTERM was queued in pendingSignals, want discarded")
		}
	}

	// 4. Under SignalUnkillableNone, peer SIGKILL to init is NOT discarded.
	{
		k := &Kernel{signalUnkillable: SignalUnkillableNone}
		task := newTask(k, initTG)
		if err := task.sendSignalTimerLocked(peerKill, false /* group */, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if task.pendingSignals.pendingSet.Load() == 0 {
			t.Errorf("peer SIGKILL was discarded under policy None, want delivered")
		}
	}

	// 5. Signals to non-init process (PID 2) are NOT discarded.
	{
		k := &Kernel{signalUnkillable: SignalUnkillableLinux}
		task := newTask(k, nonInitTG)
		if err := task.sendSignalTimerLocked(peerKill, false /* group */, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if task.pendingSignals.pendingSet.Load() == 0 {
			t.Errorf("peer SIGKILL to non-init was discarded, want delivered")
		}
	}

	// 6. Traced tasks are exempt and do not have signals discarded.
	{
		k := &Kernel{signalUnkillable: SignalUnkillableLinux}
		task := newTask(k, initTG)
		task.ptraceTracer.Store(&Task{})
		if err := task.sendSignalTimerLocked(peerKill, false /* group */, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if task.pendingSignals.pendingSet.Load() == 0 {
			t.Errorf("peer SIGKILL to traced init was discarded, want delivered")
		}
	}

	// 7. Forced SIGKILL (SI_KERNEL) to init is NOT discarded.
	{
		k := &Kernel{signalUnkillable: SignalUnkillableLinux}
		task := newTask(k, initTG)
		if err := task.sendSignalTimerLocked(forcedKill, false /* group */, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if task.pendingSignals.pendingSet.Load() == 0 {
			t.Errorf("forced SIGKILL was discarded, want delivered")
		}
	}

	// 8. Handled signals are NOT discarded.
	{
		k := &Kernel{signalUnkillable: SignalUnkillableLinux}
		handledTG := &ThreadGroup{
			signalHandlers: NewSignalHandlers(),
		}
		handledTG.signalHandlers.actions[linux.SIGTERM] = linux.SigAction{Handler: 0x1000}
		handledTG.pidWithinNS.Store(int32(initTID))
		task := newTask(k, handledTG)
		if err := task.sendSignalTimerLocked(peerTerm, false /* group */, nil); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if task.pendingSignals.pendingSet.Load() == 0 {
			t.Errorf("handled peer SIGTERM was discarded, want delivered")
		}
	}
}
