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

package boot

import (
	"fmt"
	"os"
	"syscall"

	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/eventchannel"
	"gvisor.dev/gvisor/pkg/log"
	rpb "gvisor.dev/gvisor/pkg/sentry/arch/registers_go_proto"
	ucspb "gvisor.dev/gvisor/pkg/sentry/kernel/uncaught_signal_go_proto"
	"gvisor.dev/gvisor/pkg/sentry/strace"
	spb "gvisor.dev/gvisor/pkg/sentry/unimpl/unimplemented_syscall_go_proto"
	"gvisor.dev/gvisor/pkg/sync"
)

func initCompatLogs(fd int) error {
	ce, err := newCompatEmitter(fd)
	if err != nil {
		return err
	}
	eventchannel.AddEmitter(ce)
	return nil
}

type compatEmitter struct {
	sink    *log.BasicLogger
	nameMap strace.SyscallMap

	// mu protects the fields below.
	mu sync.Mutex

	// trackers map syscall number to the respective tracker instance.
	// Protected by 'mu'.
	trackers map[uint64]syscallTracker
}

func newCompatEmitter(logFD int) (*compatEmitter, error) {
	nameMap, ok := getSyscallNameMap()
	if !ok {
		return nil, fmt.Errorf("syscall table not found")
	}

	c := &compatEmitter{
		// Always logs to default logger.
		sink:     log.Log(),
		nameMap:  nameMap,
		trackers: make(map[uint64]syscallTracker),
	}

	if logFD > 0 {
		f := os.NewFile(uintptr(logFD), "user log file")
		target := &log.MultiEmitter{c.sink, log.K8sJSONEmitter{&log.Writer{Next: f}}}
		c.sink = &log.BasicLogger{Level: log.Info, Emitter: target}
	}
	return c, nil
}

// Emit implements eventchannel.Emitter.
func (c *compatEmitter) Emit(msg proto.Message) (bool, error) {
	switch m := msg.(type) {
	case *spb.UnimplementedSyscall:
		c.emitUnimplementedSyscall(m)
	case *ucspb.UncaughtSignal:
		c.emitUncaughtSignal(m)
	}

	return false, nil
}

func (c *compatEmitter) emitUnimplementedSyscall(us *spb.UnimplementedSyscall) {
	regs := us.Registers

	c.mu.Lock()
	defer c.mu.Unlock()

	sysnr := syscallNum(regs)
	tr := c.trackers[sysnr]
	if tr == nil {
		switch sysnr {
		case syscall.SYS_PRCTL:
			// args: cmd, ...
			tr = newArgsTracker(0)

		case syscall.SYS_IOCTL, syscall.SYS_EPOLL_CTL, syscall.SYS_SHMCTL, syscall.SYS_FUTEX, syscall.SYS_FALLOCATE:
			// args: fd/addr, cmd, ...
			tr = newArgsTracker(1)

		case syscall.SYS_GETSOCKOPT, syscall.SYS_SETSOCKOPT:
			// args: fd, level, name, ...
			tr = newArgsTracker(1, 2)

		case syscall.SYS_SEMCTL:
			// args: semid, semnum, cmd, ...
			tr = newArgsTracker(2)

		default:
			tr = newArchArgsTracker(sysnr)
			if tr == nil {
				tr = &onceTracker{}
			}
		}
		c.trackers[sysnr] = tr
	}

	if tr.shouldReport(regs) {
		name := c.nameMap.Name(uintptr(sysnr))
		c.sink.Infof("Unsupported syscall %s(%#x,%#x,%#x,%#x,%#x,%#x). It is "+
			"likely that you can safely ignore this message and that this is not "+
			"the cause of any error. Please, refer to %s/%s for more information.",
			name, argVal(0, regs), argVal(1, regs), argVal(2, regs), argVal(3, regs),
			argVal(4, regs), argVal(5, regs), syscallLink, name)

		tr.onReported(regs)
	}
}

func (c *compatEmitter) emitUncaughtSignal(msg *ucspb.UncaughtSignal) {
	sig := syscall.Signal(msg.SignalNumber)
	c.sink.Infof(
		"Uncaught signal: %q (%d), PID: %d, TID: %d, fault addr: %#x",
		sig, msg.SignalNumber, msg.Pid, msg.Tid, msg.FaultAddr)
}

// Close implements eventchannel.Emitter.
func (c *compatEmitter) Close() error {
	c.sink = nil
	return nil
}

// syscallTracker interface allows filters to apply differently depending on
// the syscall and arguments.
type syscallTracker interface {
	// shouldReport returns true is the syscall should be reported.
	shouldReport(regs *rpb.Registers) bool

	// onReported marks the syscall as reported.
	onReported(regs *rpb.Registers)
}

// onceTracker reports only a single time, used for most syscalls.
type onceTracker struct {
	reported bool
}

func (o *onceTracker) shouldReport(_ *rpb.Registers) bool {
	return !o.reported
}

func (o *onceTracker) onReported(_ *rpb.Registers) {
	o.reported = true
}

// argsTracker reports only once for each different combination of arguments.
// It's used for generic syscalls like ioctl to report once per 'cmd'.
type argsTracker struct {
	// argsIdx is the syscall arguments to use as unique ID.
	argsIdx  []int
	reported map[string]struct{}
	count    int
}

func newArgsTracker(argIdx ...int) *argsTracker {
	return &argsTracker{argsIdx: argIdx, reported: make(map[string]struct{})}
}

// key returns the command based on the syscall argument index.
func (a *argsTracker) key(regs *rpb.Registers) string {
	var rv string
	for _, idx := range a.argsIdx {
		rv += fmt.Sprintf("%d|", argVal(idx, regs))
	}
	return rv
}

func (a *argsTracker) shouldReport(regs *rpb.Registers) bool {
	if a.count >= reportLimit {
		return false
	}
	_, ok := a.reported[a.key(regs)]
	return !ok
}

func (a *argsTracker) onReported(regs *rpb.Registers) {
	a.count++
	a.reported[a.key(regs)] = struct{}{}
}
