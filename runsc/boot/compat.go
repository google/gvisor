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

package boot

import (
	"fmt"
	"os"
	"sync"
	"syscall"

	"github.com/golang/protobuf/proto"
	"gvisor.googlesource.com/gvisor/pkg/abi"
	"gvisor.googlesource.com/gvisor/pkg/eventchannel"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	rpb "gvisor.googlesource.com/gvisor/pkg/sentry/arch/registers_go_proto"
	"gvisor.googlesource.com/gvisor/pkg/sentry/strace"
	spb "gvisor.googlesource.com/gvisor/pkg/sentry/unimpl/unimplemented_syscall_go_proto"
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
	nameMap, ok := strace.Lookup(abi.Linux, arch.AMD64)
	if !ok {
		return nil, fmt.Errorf("amd64 Linux syscall table not found")
	}

	c := &compatEmitter{
		// Always logs to default logger.
		sink:     log.Log(),
		nameMap:  nameMap,
		trackers: make(map[uint64]syscallTracker),
	}

	if logFD > 0 {
		f := os.NewFile(uintptr(logFD), "user log file")
		target := log.MultiEmitter{c.sink, log.GoogleEmitter{&log.Writer{Next: f}}}
		c.sink = &log.BasicLogger{Level: log.Info, Emitter: target}
	}
	return c, nil
}

// Emit implements eventchannel.Emitter.
func (c *compatEmitter) Emit(msg proto.Message) (hangup bool, err error) {
	// Only interested in UnimplementedSyscall, skip the rest.
	us, ok := msg.(*spb.UnimplementedSyscall)
	if !ok {
		return false, nil
	}
	regs := us.Registers.GetArch().(*rpb.Registers_Amd64).Amd64

	c.mu.Lock()
	defer c.mu.Unlock()

	sysnr := regs.OrigRax
	tr := c.trackers[sysnr]
	if tr == nil {
		switch sysnr {
		case syscall.SYS_PRCTL, syscall.SYS_ARCH_PRCTL:
			tr = newCmdTracker(0)

		case syscall.SYS_IOCTL, syscall.SYS_EPOLL_CTL, syscall.SYS_SHMCTL:
			tr = newCmdTracker(1)

		default:
			tr = &onceTracker{}
		}
		c.trackers[sysnr] = tr
	}
	if tr.shouldReport(regs) {
		c.sink.Infof("Unsupported syscall: %s, regs: %+v", c.nameMap.Name(uintptr(sysnr)), regs)
		tr.onReported(regs)
	}
	return false, nil
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
	shouldReport(regs *rpb.AMD64Registers) bool

	// onReported marks the syscall as reported.
	onReported(regs *rpb.AMD64Registers)
}

// onceTracker reports only a single time, used for most syscalls.
type onceTracker struct {
	reported bool
}

func (o *onceTracker) shouldReport(_ *rpb.AMD64Registers) bool {
	return !o.reported
}

func (o *onceTracker) onReported(_ *rpb.AMD64Registers) {
	o.reported = true
}
