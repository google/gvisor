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
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
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

// TestSignalForcedFrom verifies that a signal is forced exactly when its sender
// has no ID in the target's PID namespace (kernel/signal.c:__send_signal_locked()).
func TestSignalForcedFrom(t *testing.T) {
	root := &PIDNamespace{}
	child := &PIDNamespace{parent: root}
	sibling := &PIDNamespace{parent: root}
	grandchild := &PIDNamespace{parent: child}
	tg := &ThreadGroup{}
	tg.pidns = child
	taskIn := func(ns *PIDNamespace) *Task {
		task := &Task{}
		task.tg = &ThreadGroup{}
		task.tg.pidns = ns
		return task
	}

	for _, tc := range []struct {
		name   string
		sender *Task
		want   bool
	}{
		{"peer in the same namespace", taskIn(child), false},
		{"descendant namespace", taskIn(grandchild), false},
		{"ancestor namespace", taskIn(root), true},
		{"sibling namespace", taskIn(sibling), true},
		{"sentry itself", nil, true},
	} {
		if got := tg.signalForcedFrom(tc.sender); got != tc.want {
			t.Errorf("%s: signalForcedFrom = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// fakeCgroup2FS is a minimal Cgroup2FS double for tests that construct a bare
// *Kernel without going through Kernel.Init(). It lets
// sendSignalTimerLocked's t.k.Cgroup2FS().EverMounted() call return false
// instead of dereferencing the nil k.cgroupRegistry.v2fs that a real Init()
// would otherwise have set up. Every other embedded method is unimplemented
// (nil) and would panic if called, but EverMounted() returning false means
// sendSignalTimerLocked never calls any of them.
type fakeCgroup2FS struct {
	vfs.FilesystemImpl
	Cgroup2FS
}

func (fakeCgroup2FS) EverMounted() bool { return false }

// sharedFakeRegistry backs Kernel.cgroupRegistry for tests below that
// construct a bare *Kernel. It's read-only (EverMounted() always returns
// false), so sharing one instance across sub-tests is safe.
var sharedFakeRegistry = func() *CgroupRegistry {
	vfsObj := &vfs.VirtualFilesystem{}
	if err := vfsObj.Init(context.Background()); err != nil {
		panic(err)
	}
	fs := &vfs.Filesystem{}
	fs.Init(vfsObj, nil /* fsType, never queried */, fakeCgroup2FS{})
	return &CgroupRegistry{v2fs: fs}
}()

// newSignalTestTask returns a task in tg that cannot be interrupted, so that a
// queued signal stays in its pending set without reaching the task's unset
// platform context.
func newSignalTestTask(k *Kernel, tg *ThreadGroup) *Task {
	task := &Task{}
	task.k = k
	task.tg = tg
	prefix := ""
	task.logPrefix.Store(&prefix)
	task.interruptChan = make(chan struct{}, 1)
	task.interruptChan <- struct{}{}
	return task
}

// newInitTestTask returns a task whose thread group is the init process of
// its PID namespace, under the given policy.
func newInitTestTask(policy SignalUnkillablePolicy) *Task {
	tg := &ThreadGroup{
		signalHandlers: NewSignalHandlers(),
	}
	tg.pidWithinNS.Store(int32(initTID))
	tg.signalUnkillable.Store(true)
	k := &Kernel{signalUnkillable: policy}
	k.cgroupRegistry = sharedFakeRegistry
	return newSignalTestTask(k, tg)
}

// TestSendSignalToInit verifies that sendSignalTimerLocked queues or discards
// signals sent to a PID namespace's init process as Linux does
// (kernel/signal.c:sig_ignored()).
func TestSendSignalToInit(t *testing.T) {
	handlerAct := linux.SigAction{Handler: 0x1000} // arbitrary user handler

	for _, tc := range []struct {
		name       string
		policy     SignalUnkillablePolicy
		nonInit    bool
		traced     bool
		handled    bool
		blocked    bool
		sig        linux.Signal
		code       int32
		forced     bool
		wantQueued bool
	}{
		{name: "peer SIGKILL discarded", policy: SignalUnkillableLinux, sig: linux.SIGKILL, code: linux.SI_USER},
		{name: "peer SIGSTOP discarded", policy: SignalUnkillableLinux, sig: linux.SIGSTOP, code: linux.SI_USER},
		{name: "peer unhandled SIGTERM discarded", policy: SignalUnkillableLinux, sig: linux.SIGTERM, code: linux.SI_USER},
		{name: "SI_KERNEL code does not force", policy: SignalUnkillableLinux, sig: linux.SIGKILL, code: linux.SI_KERNEL},
		{name: "SI_QUEUE with PID 0 does not force", policy: SignalUnkillableLinux, sig: linux.SIGKILL, code: linux.SI_QUEUE},
		{name: "SI_TIMER does not force", policy: SignalUnkillableLinux, sig: linux.SIGKILL, code: linux.SI_TIMER},
		{name: "forced SIGKILL queued", policy: SignalUnkillableLinux, sig: linux.SIGKILL, code: linux.SI_USER, forced: true, wantQueued: true},
		{name: "forced SIGSTOP queued", policy: SignalUnkillableLinux, sig: linux.SIGSTOP, code: linux.SI_USER, forced: true, wantQueued: true},
		{name: "forced unhandled SIGTERM discarded", policy: SignalUnkillableLinux, sig: linux.SIGTERM, code: linux.SI_USER, forced: true},
		{name: "peer handled SIGTERM queued", policy: SignalUnkillableLinux, handled: true, sig: linux.SIGTERM, code: linux.SI_USER, wantQueued: true},
		{name: "peer blocked SIGTERM queued", policy: SignalUnkillableLinux, blocked: true, sig: linux.SIGTERM, code: linux.SI_USER, wantQueued: true},
		{name: "traced init discards peer SIGKILL", policy: SignalUnkillableLinux, traced: true, sig: linux.SIGKILL, code: linux.SI_USER},
		{name: "traced init queues peer SIGTERM", policy: SignalUnkillableLinux, traced: true, sig: linux.SIGTERM, code: linux.SI_USER, wantQueued: true},
		{name: "traced init queues forced SIGSTOP", policy: SignalUnkillableLinux, traced: true, sig: linux.SIGSTOP, code: linux.SI_USER, forced: true, wantQueued: true},
		{name: "policy none queues peer SIGKILL", policy: SignalUnkillableNone, sig: linux.SIGKILL, code: linux.SI_USER, wantQueued: true},
		{name: "non-init queues peer SIGKILL", policy: SignalUnkillableLinux, nonInit: true, sig: linux.SIGKILL, code: linux.SI_USER, wantQueued: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			task := newInitTestTask(tc.policy)
			if tc.nonInit {
				task.tg.pidWithinNS.Store(2)
				task.tg.signalUnkillable.Store(false)
			}
			if tc.traced {
				task.ptraceTracer.Store(&Task{})
			}
			if tc.handled {
				task.tg.signalHandlers.mu.Lock()
				task.tg.signalHandlers.actions[tc.sig] = handlerAct
				task.tg.signalHandlers.mu.Unlock()
			}
			if tc.blocked {
				task.signalMask.Store(uint64(linux.SignalSetOf(tc.sig)))
			}
			info := &linux.SignalInfo{Signo: int32(tc.sig), Code: tc.code}
			if tc.code == linux.SI_USER {
				info.SetPID(2)
			}
			timer := &IntervalTimer{}
			task.tg.signalHandlers.mu.Lock()
			err := task.sendSignalTimerLocked(info, false /* group */, tc.forced, timer)
			task.tg.signalHandlers.mu.Unlock()
			if err != nil {
				t.Fatalf("sendSignalTimerLocked: %v", err)
			}
			queued := task.pendingSignals.pendingSet.Load() != 0
			if queued != tc.wantQueued {
				t.Errorf("signal queued = %t, want %t", queued, tc.wantQueued)
			}
			wantOverrun := uint64(0)
			if !tc.wantQueued {
				wantOverrun = 1
			}
			if timer.overrunCur != wantOverrun {
				t.Errorf("timer.overrunCur = %d, want %d", timer.overrunCur, wantOverrun)
			}
			if tc.sig == linux.SIGKILL && !tc.wantQueued && task.tg.exiting {
				t.Errorf("discarded SIGKILL marked the thread group as exiting")
			}
		})
	}
}

// TestInitSignalDropped verifies the dequeue-time rule that keeps a PID
// namespace's init process alive under Linux SIGNAL_UNKILLABLE semantics
// (kernel/signal.c:get_signal()).
func TestInitSignalDropped(t *testing.T) {
	dflAct := linux.SigAction{Handler: linux.SIG_DFL}
	handlerAct := linux.SigAction{Handler: 0x1000} // arbitrary user handler

	for _, tc := range []struct {
		name    string
		policy  SignalUnkillablePolicy
		nonInit bool
		sig     linux.Signal
		act     linux.SigAction
		want    bool
	}{
		{name: "unhandled SIGTERM dropped", policy: SignalUnkillableLinux, sig: linux.SIGTERM, act: dflAct, want: true},
		{name: "unhandled SIGSEGV dropped", policy: SignalUnkillableLinux, sig: linux.SIGSEGV, act: dflAct, want: true},
		{name: "unhandled SIGTSTP dropped", policy: SignalUnkillableLinux, sig: linux.SIGTSTP, act: dflAct, want: true},
		{name: "handled SIGTERM delivered", policy: SignalUnkillableLinux, sig: linux.SIGTERM, act: handlerAct, want: false},
		{name: "SIGKILL kills", policy: SignalUnkillableLinux, sig: linux.SIGKILL, act: dflAct, want: false},
		{name: "SIGSTOP stops", policy: SignalUnkillableLinux, sig: linux.SIGSTOP, act: dflAct, want: false},
		{name: "policy none delivers", policy: SignalUnkillableNone, sig: linux.SIGTERM, act: dflAct, want: false},
		{name: "non-init delivers", policy: SignalUnkillableLinux, nonInit: true, sig: linux.SIGTERM, act: dflAct, want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			task := newInitTestTask(tc.policy)
			if tc.nonInit {
				task.tg.pidWithinNS.Store(2)
				task.tg.signalUnkillable.Store(false)
			}
			if got := task.initSignalDropped(tc.sig, tc.act); got != tc.want {
				t.Errorf("initSignalDropped(%v, %+v) = %t, want %t", tc.sig, tc.act, got, tc.want)
			}
		})
	}
}

// TestForceSignalOnInit verifies that a forced signal that will take its
// default action makes an init process killable again
// (kernel/signal.c:force_sig_info_to_task()), so that a faulting init exits.
func TestForceSignalOnInit(t *testing.T) {
	handlerAct := linux.SigAction{Handler: 0x1000} // arbitrary user handler

	for _, tc := range []struct {
		name           string
		traced         bool
		handled        bool
		blocked        bool
		unconditional  bool
		wantUnkillable bool
	}{
		{name: "default action clears", wantUnkillable: false},
		{name: "blocked default action clears", blocked: true, wantUnkillable: false},
		{name: "handler keeps", handled: true, wantUnkillable: true},
		{name: "blocked handler clears", handled: true, blocked: true, wantUnkillable: false},
		{name: "traced keeps", traced: true, wantUnkillable: true},
		{name: "traced unconditional keeps", traced: true, unconditional: true, wantUnkillable: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			task := newInitTestTask(SignalUnkillableLinux)
			if tc.traced {
				task.ptraceTracer.Store(&Task{})
			}
			if tc.handled {
				task.tg.signalHandlers.mu.Lock()
				task.tg.signalHandlers.actions[linux.SIGSEGV] = handlerAct
				task.tg.signalHandlers.mu.Unlock()
			}
			if tc.blocked {
				task.signalMask.Store(uint64(linux.SignalSetOf(linux.SIGSEGV)))
			}
			task.tg.signalHandlers.mu.Lock()
			task.forceSignalLocked(linux.SIGSEGV, tc.unconditional)
			task.tg.signalHandlers.mu.Unlock()
			if got := task.tg.signalUnkillable.Load(); got != tc.wantUnkillable {
				t.Fatalf("signalUnkillable = %t, want %t", got, tc.wantUnkillable)
			}
			if err := task.SendSignal(SignalInfoPriv(linux.SIGSEGV)); err != nil {
				t.Fatalf("SendSignal: %v", err)
			}
			if task.pendingSignals.pendingSet.Load() == 0 {
				t.Errorf("SIGSEGV was discarded after forceSignalLocked, want queued")
			}
			task.tg.signalHandlers.mu.Lock()
			act := task.tg.signalHandlers.actions[linux.SIGSEGV]
			task.tg.signalHandlers.mu.Unlock()
			if !tc.traced && !tc.handled && tc.wantUnkillable == false && task.initSignalDropped(linux.SIGSEGV, act) {
				t.Errorf("SIGSEGV would be dropped at delivery after forceSignalLocked")
			}
		})
	}
}
