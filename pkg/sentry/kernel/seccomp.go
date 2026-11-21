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

package kernel

import (
	"fmt"
	"strings"

	"golang.org/x/sys/unix"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/abi/sentry"
	"gvisor.dev/gvisor/pkg/bpf"
	"gvisor.dev/gvisor/pkg/errors/linuxerr"
	"gvisor.dev/gvisor/pkg/hostarch"
	"gvisor.dev/gvisor/pkg/sentry/arch"
)

const (
	maxSyscallFilterInstructions = 1 << 15

	// seccompCacheableInputSize is the size of the seccomp_data ABI prefix
	// that holds the syscall number and audit architecture. Reads beyond it
	// cannot be cached by syscall number.
	seccompCacheableInputSize = 8

	// noBPFAction is an invalid seccomp action code. It means that a syscall
	// number has no action.
	noBPFAction = linux.SECCOMP_RET_ACTION_FULL
)

// SyscallFilter is one seccomp filter. Immutable.
//
// +stateify savable
type SyscallFilter struct {
	// program is the BPF program of the filter.
	// If `fixed` is non-nil, `program` is not necessarily correct for the
	// syscalls that have a fixed action.
	program bpf.Program

	// fixed holds the actions that depend on the syscall number only.
	// It may be nil.
	fixed *fixedSyscallActions
}

// fixedSyscallActions maps syscall numbers to seccomp actions for one
// architecture.
//
// +stateify savable
type fixedSyscallActions struct {
	// auditNumber is the AUDIT_ARCH_* constant that `actions` applies to.
	auditNumber uint32

	// actions is indexed by syscall number. `noBPFAction` means that
	// the syscall has no fixed action.
	actions [sentry.MaxSyscallNum + 1]linux.BPFAction
}

// NewSyscallFilter returns a filter that evaluates `program` for all
// syscalls.
func NewSyscallFilter(program bpf.Program) SyscallFilter {
	return SyscallFilter{program: program}
}

// NewSyscallFilterWithFixedActions returns a filter for architecture
// `auditNumber` that does not evaluate `program` for syscalls with a fixed
// action.
//
// `fixedAction` returns the action for a syscall number, and whether this
// action is fixed. An action is fixed when it does not depend on the syscall
// arguments or on the instruction pointer.
// `program` must return the correct action for all other syscalls, for
// syscall numbers outside [0, `sentry.MaxSyscallNum`], and for other
// architectures.
func NewSyscallFilterWithFixedActions(auditNumber uint32, program bpf.Program, fixedAction func(sysno int32) (linux.BPFAction, bool)) SyscallFilter {
	fixed := &fixedSyscallActions{auditNumber: auditNumber}
	for sysno := range fixed.actions {
		action, ok := fixedAction(int32(sysno))
		switch {
		case !ok:
			action = noBPFAction
		case action == noBPFAction:
			panic(fmt.Sprintf("syscall %d has invalid fixed seccomp action %#x", sysno, uint32(action)))
		}
		fixed.actions[sysno] = action
	}
	return SyscallFilter{program: program, fixed: fixed}
}

// String returns a human-readable description of the filter.
func (f SyscallFilter) String() string {
	var b strings.Builder
	if f.fixed != nil {
		// Group the syscall numbers by action, in order of first use.
		var actions []linux.BPFAction
		sysnos := make(map[linux.BPFAction][]int)
		for sysno, action := range f.fixed.actions {
			if _, ok := sysnos[action]; !ok {
				actions = append(actions, action)
			}
			sysnos[action] = append(sysnos[action], sysno)
		}
		fmt.Fprintf(&b, "Fixed actions for architecture %#x:\n", f.fixed.auditNumber)
		for _, action := range actions {
			if action == noBPFAction {
				continue
			}
			fmt.Fprintf(&b, "  %#x (%v): syscalls %s\n", uint32(action), action, formatRanges(sysnos[action]))
		}
		fmt.Fprintf(&b, "No fixed action: syscalls %s\n", formatRanges(sysnos[noBPFAction]))
		b.WriteString("Program for the syscalls with no fixed action:\n")
	}
	decoded, err := bpf.DecodeProgram(f.program)
	if err != nil {
		fmt.Fprintf(&b, "cannot decode program: %v\n", err)
	} else {
		b.WriteString(decoded)
	}
	return b.String()
}

// formatRanges formats sorted numbers as a list of ranges, such as "1-3, 7".
// It returns "none" if there are no numbers.
func formatRanges(sorted []int) string {
	if len(sorted) == 0 {
		return "none"
	}
	var b strings.Builder
	for i := 0; i < len(sorted); {
		j := i
		for j+1 < len(sorted) && sorted[j+1] == sorted[j]+1 {
			j++
		}
		if b.Len() > 0 {
			b.WriteString(", ")
		}
		if i == j {
			fmt.Fprintf(&b, "%d", sorted[i])
		} else {
			fmt.Fprintf(&b, "%d-%d", sorted[i], sorted[j])
		}
		i = j + 1
	}
	return b.String()
}

// ProgramLength returns the number of instructions of the BPF program of the
// filter.
func (f SyscallFilter) ProgramLength() int {
	return f.program.Length()
}

// FixedAction returns the fixed action for `sysno` on architecture
// `auditNumber`, if there is one.
func (f SyscallFilter) FixedAction(sysno int32, auditNumber uint32) (linux.BPFAction, bool) {
	if f.fixed == nil || f.fixed.auditNumber != auditNumber || sysno < 0 || sysno > sentry.MaxSyscallNum {
		return 0, false
	}
	action := f.fixed.actions[sysno]
	return action, action != noBPFAction
}

// Evaluate returns the result of the filter for `input`, which is a
// serialized `linux.SeccompData`.
func (f SyscallFilter) Evaluate(input bpf.Input) (uint32, error) {
	if f.fixed != nil {
		if len(input) < seccompCacheableInputSize {
			return 0, fmt.Errorf("seccomp input has %d bytes, expected at least %d", len(input), seccompCacheableInputSize)
		}
		sysno := int32(hostarch.ByteOrder.Uint32(input))
		auditNumber := hostarch.ByteOrder.Uint32(input[4:])
		if action, ok := f.FixedAction(sysno, auditNumber); ok {
			return uint32(action), nil
		}
	}
	return bpf.Exec[bpf.NativeEndian](f.program, input)
}

// taskSeccomp holds seccomp-related data for a `Task`.
//
// +stateify savable
type taskSeccomp struct {
	// filters is the list of seccomp filters that are applied to the task,
	// in the order in which they were installed.
	filters []SyscallFilter

	// cache maps syscall numbers to the action to take for that syscall number.
	// It is only populated for syscalls where determining this action does not
	// involve any input data other than the architecture and the syscall
	// number in any of `filters`.
	// If any other input is necessary, the cache stores `noBPFAction`
	// to indicate that this syscall number's rules are not cacheable.
	cache [sentry.MaxSyscallNum + 1]linux.BPFAction

	// cacheAuditNumber is the AUDIT_ARCH_* constant of the task image used
	// at the time of computing `cache`.
	cacheAuditNumber uint32
}

// copy returns a copy of this taskSeccomp, including its cache. Cache lookups
// check cacheAuditNumber before using entries for the current architecture.
func (ts *taskSeccomp) copy() *taskSeccomp {
	return &taskSeccomp{
		filters:          append(([]SyscallFilter)(nil), ts.filters...),
		cacheAuditNumber: ts.cacheAuditNumber,
		cache:            ts.cache,
	}
}

// dataAsBPFInput returns a serialized BPF program, only valid on the current task
// goroutine.
//
// Note: this is called for every syscall, which is a very hot path.
func dataAsBPFInput(t *Task, d *linux.SeccompData) bpf.Input {
	buf := t.CopyScratchBuffer(d.SizeBytes())
	d.MarshalUnsafe(buf)
	return buf[:d.SizeBytes()]
}

func seccompSiginfo(t *Task, errno, sysno int32, ip hostarch.Addr) *linux.SignalInfo {
	si := &linux.SignalInfo{
		Signo: int32(linux.SIGSYS),
		Errno: errno,
		Code:  linux.SYS_SECCOMP,
	}
	si.SetCallAddr(uint64(ip))
	si.SetSyscall(sysno)
	si.SetArch(t.SyscallTable().AuditNumber)
	return si
}

// checkSeccompSyscall applies the task's seccomp filters before the execution
// of syscall sysno at instruction pointer ip. (These parameters must be passed
// in because vsyscalls do not use the values in t.Arch().)
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) checkSeccompSyscall(sysno int32, args arch.SyscallArguments, ip hostarch.Addr) linux.BPFAction {
	result := linux.BPFAction(t.evaluateSyscallFilters(sysno, args, ip))
	// Extract the action using SECCOMP_RET_ACTION_FULL rather than
	// SECCOMP_RET_ACTION: SECCOMP_RET_ACTION (0x7fff0000) would truncate
	// SECCOMP_RET_KILL_PROCESS (0x80000000) to SECCOMP_RET_KILL_THREAD.
	action := result & linux.SECCOMP_RET_ACTION_FULL
	switch action {
	case linux.SECCOMP_RET_TRAP:
		// "Results in the kernel sending a SIGSYS signal to the triggering
		// task without executing the system call. ... The SECCOMP_RET_DATA
		// portion of the return value will be passed as si_errno." -
		// Documentation/prctl/seccomp_filter.txt
		//
		// The signal is forced, analogous to Linux's
		// kernel/seccomp.c:seccomp_send_sigsys() => force_sig_seccomp().
		t.forceSignal(linux.SIGSYS, false /* unconditional */)
		t.SendSignal(seccompSiginfo(t, int32(result.Data()), sysno, ip))
		// Match Linux's syscall_rollback(): the return register holds the
		// syscall number on x86_64 and the first argument on arm64.
		switch t.Arch().Arch() {
		case arch.ARM64:
			t.Arch().SetReturn(args[0].Value)
		default:
			t.Arch().SetReturn(uintptr(sysno))
		}

	case linux.SECCOMP_RET_ERRNO:
		// "Results in the lower 16-bits of the return value being passed to
		// userland as the errno without executing the system call."
		t.Arch().SetReturn(-uintptr(result.Data()))

	case linux.SECCOMP_RET_TRACE:
		// "When returned, this value will cause the kernel to attempt to
		// notify a ptrace()-based tracer prior to executing the system call.
		// If there is no tracer present, -ENOSYS is returned to userland and
		// the system call is not executed."
		if !t.ptraceSeccomp(result.Data()) {
			// This useless-looking temporary is needed because Go.
			tmp := uintptr(unix.ENOSYS)
			t.Arch().SetReturn(-tmp)
			return linux.SECCOMP_RET_ERRNO
		}

	case linux.SECCOMP_RET_LOG:
		t.Debugf("Syscall %d: logged by seccomp", sysno)
		return linux.SECCOMP_RET_ALLOW

	case linux.SECCOMP_RET_ALLOW:
		// "Results in the system call being executed."

	case linux.SECCOMP_RET_KILL_PROCESS:
		// "Results in the entire process being killed immediately without
		// executing the system call. The exit status of the process will be
		// SIGSYS, not SIGKILL." - Documentation/prctl/seccomp_filter.txt

	case linux.SECCOMP_RET_KILL_THREAD:
		// "Results in the task exiting immediately without executing the
		// system call. The exit status of the task will be SIGSYS, not
		// SIGKILL."

	default:
		// consistent with Linux
		return linux.SECCOMP_RET_KILL_THREAD
	}
	return action
}

func (t *Task) evaluateSyscallFilters(sysno int32, args arch.SyscallArguments, ip hostarch.Addr) uint32 {
	ret := uint32(linux.SECCOMP_RET_ALLOW)
	ts := t.seccomp.Load()
	if ts == nil {
		return ret
	}
	arch := t.image.st.AuditNumber
	if arch == ts.cacheAuditNumber && sysno >= 0 && sysno <= sentry.MaxSyscallNum {
		if cached := ts.cache[sysno]; cached != noBPFAction {
			return uint32(cached)
		}
	}

	data := linux.SeccompData{
		Nr:                 sysno,
		Arch:               arch,
		InstructionPointer: uint64(ip),
	}
	// data.args is []uint64 and args is []arch.SyscallArgument (uintptr), so
	// we can't do any slicing tricks or even use copy/append here.
	for i, arg := range args {
		if i >= len(data.Args) {
			break
		}
		data.Args[i] = arg.Uint64()
	}
	input := dataAsBPFInput(t, &data)

	// "Every filter successfully installed will be evaluated (in reverse
	// order) for each system call the task makes." - kernel/seccomp.c
	for i := len(ts.filters) - 1; i >= 0; i-- {
		thisRet, err := ts.filters[i].Evaluate(input)
		if err != nil {
			t.Debugf("seccomp-bpf filter %d returned error: %v", i, err)
			thisRet = uint32(linux.SECCOMP_RET_KILL_THREAD)
		}
		// "If multiple filters exist, the return value for the evaluation of a
		// given system call will always use the highest precedent value." -
		// Documentation/prctl/seccomp_filter.txt
		//
		// (Note that this contradicts prctl(2): "If the filters permit prctl()
		// calls, then additional filters can be added; they are run in order
		// until the first non-allow result is seen." prctl(2) is incorrect.)
		//
		// "The ordering ensures that a min_t() over composed return values
		// always selects the least permissive choice." -
		// include/uapi/linux/seccomp.h
		//
		// Like Linux's seccomp_run_filters() (ACTION_ONLY()), compare the
		// SECCOMP_RET_ACTION_FULL-masked actions as signed integers. This is
		// required so that SECCOMP_RET_KILL_PROCESS (0x80000000) sorts before
		// SECCOMP_RET_KILL_THREAD (0x0) and takes precedence; masking with
		// SECCOMP_RET_ACTION (0x7fff0000) would truncate KILL_PROCESS to
		// KILL_THREAD.
		if int32(thisRet&linux.SECCOMP_RET_ACTION_FULL) < int32(ret&linux.SECCOMP_RET_ACTION_FULL) {
			ret = thisRet
		}
	}

	return ret
}

// checkFilterCacheability executes `program` on the given `input`, and
// checks if its result is cacheable. If it is, it returns that result.
func checkFilterCacheability(program bpf.Program, input bpf.Input, metrics *bpf.ExecutionMetrics) (uint32, bool) {
	if err := bpf.InstrumentedExecWithMetrics[bpf.NativeEndian](program, input, metrics); err != nil {
		return 0, false
	}
	for offset, accessed := range metrics.InputAccessed {
		if accessed && offset >= seccompCacheableInputSize {
			return 0, false
		}
	}
	return metrics.ReturnValue, true
}

// populateCache recomputes `ts.cache` from `ts.filters`.
//
// Preconditions: No task can evaluate `ts` at the same time.
func (ts *taskSeccomp) populateCache(t *Task) {
	auditNumber := t.image.st.AuditNumber
	// cache holds the smallest result so far for each syscall number, or
	// `noBPFAction` if a filter is not cacheable for it.
	var cache [sentry.MaxSyscallNum + 1]linux.BPFAction
	for sysno := range cache {
		cache[sysno] = linux.SECCOMP_RET_ALLOW
	}
	// input only differs by syscall number between filter executions.
	sd := linux.SeccompData{Arch: auditNumber}
	input := bpf.Input(make([]byte, sd.SizeBytes()))
	sd.MarshalBytes(input)
	var metrics bpf.ExecutionMetrics

	// Apply the filters in the same way as `evaluateSyscallFilters`: iterate
	// through them backwards, and keep the smallest result for each syscall
	// number. A syscall number is not cacheable if any filter is not
	// cacheable for it.
	for i := len(ts.filters) - 1; i >= 0; i-- {
		f := &ts.filters[i]
		for sysno := int32(0); sysno <= sentry.MaxSyscallNum; sysno++ {
			cached := cache[sysno]
			if cached == noBPFAction {
				continue
			}
			result, ok := f.FixedAction(sysno, auditNumber)
			if !ok {
				hostarch.ByteOrder.PutUint32(input, uint32(sysno))
				ret, cacheable := checkFilterCacheability(f.program, input, &metrics)
				if !cacheable {
					cache[sysno] = noBPFAction
					continue
				}
				result = linux.BPFAction(ret)
			}
			// See the note in `evaluateSyscallFilters`: compare
			// SECCOMP_RET_ACTION_FULL-masked actions as signed integers so
			// that SECCOMP_RET_KILL_PROCESS takes precedence.
			if int32(result&linux.SECCOMP_RET_ACTION_FULL) < int32(cached&linux.SECCOMP_RET_ACTION_FULL) {
				cache[sysno] = result
			}
		}
	}
	ts.cache = cache
	ts.cacheAuditNumber = auditNumber
}

// AppendSyscallFilter adds f as a system call filter.
//
// Preconditions: The caller must be running on the task goroutine.
func (t *Task) AppendSyscallFilter(f SyscallFilter, syncAll bool) error {
	// While syscallFilters are an atomic.Value we must take the mutex to prevent
	// our read-copy-update from happening while another task is syncing syscall
	// filters to us, this keeps the filters in a consistent state.
	t.tg.signalHandlers.mu.Lock()
	defer t.tg.signalHandlers.mu.Unlock()

	// Cap the combined length of all syscall filters (plus a penalty of 4
	// instructions per filter beyond the first) to maxSyscallFilterInstructions.
	// This restriction is inherited from Linux.
	totalLength := f.ProgramLength()
	newSeccomp := &taskSeccomp{}

	if ts := t.seccomp.Load(); ts != nil {
		for _, existing := range ts.filters {
			totalLength += existing.ProgramLength() + 4
		}
		newSeccomp.filters = append(newSeccomp.filters, ts.filters...)
	}

	if totalLength > maxSyscallFilterInstructions {
		return linuxerr.ENOMEM
	}

	newSeccomp.filters = append(newSeccomp.filters, f)
	newSeccomp.populateCache(t)
	t.seccomp.Store(newSeccomp)

	if syncAll {
		currentNoNewPrivs := t.GetNoNewPrivs()
		for ot := t.tg.tasks.Front(); ot != nil; ot = ot.Next() {
			if ot != t {
				// Disallow threads from getting around the NoNewPrivs restriction through a NoNewPrivs
				// sibling that does a tsync.
				if currentNoNewPrivs {
					ot.SetNoNewPrivs()
				}
				ot.seccomp.Store(newSeccomp.copy())
			}
		}
	}

	return nil
}

// AppendSyscallFilterAndTsync adds the program p and syncs it to all other tasks in the thread
// group. Unlike AppendSyscallFilter, it serializes with a concurrent execve.
//
// Preconditions: Must be called from a system call handler on the task goroutine.
func (t *Task) AppendSyscallFilterAndTsync(p bpf.Program) *SyscallControl {
	// Serialize with execve(2) to ensure that a sibling doesn't change its creds or NoNewPrivs
	// while we're syncing the seccomp filter, see kernel/seccomp.c:seccomp_sync_threads().
	t.execveCredsMutexStartLock(t.tg)
	r := runSeccompAfterExecveCredsLock{
		program: p,
	}
	return &SyscallControl{next: &r, ignoreReturn: false}
}

// The runSeccompAfterExecveCredsLock state continues seccomp tsync after the lock that serializes
// it with execve has been acquired.
//
// +stateify savable
type runSeccompAfterExecveCredsLock struct {
	program bpf.Program
}

func (r *runSeccompAfterExecveCredsLock) execute(t *Task) taskRunState {
	if t.killed() {
		// execveCredsMutexUnlock() will not pass us the lock after we were killed, so there is no
		// race in loading execveCredsMutexOwner without a lock.
		if t.execveCredsMutexOwner != nil {
			t.execveCredsMutexUnlock()
		}
		return (*runInterrupt)(nil)
	}

	defer t.execveCredsMutexUnlock()
	if err := t.AppendSyscallFilter(NewSyscallFilter(r.program), true); err != nil {
		return t.doSyscallError(err)
	}
	return (*runSyscallExit)(nil)
}

// SeccompMode returns a SECCOMP_MODE_* constant indicating the task's current
// seccomp syscall filtering mode, appropriate for both prctl(PR_GET_SECCOMP)
// and /proc/[pid]/status.
func (t *Task) SeccompMode() int {
	if ts := t.seccomp.Load(); ts != nil && len(ts.filters) > 0 {
		return linux.SECCOMP_MODE_FILTER
	}
	return linux.SECCOMP_MODE_NONE
}
