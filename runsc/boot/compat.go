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

	"github.com/golang/protobuf/proto"
	"gvisor.googlesource.com/gvisor/pkg/abi"
	"gvisor.googlesource.com/gvisor/pkg/eventchannel"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	rpb "gvisor.googlesource.com/gvisor/pkg/sentry/arch/registers_go_proto"
	"gvisor.googlesource.com/gvisor/pkg/sentry/strace"
	spb "gvisor.googlesource.com/gvisor/pkg/sentry/syscalls/unimplemented_syscall_go_proto"
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
}

func newCompatEmitter(logFD int) (*compatEmitter, error) {
	// Always logs to default logger.
	nameMap, ok := strace.Lookup(abi.Linux, arch.AMD64)
	if !ok {
		return nil, fmt.Errorf("amd64 Linux syscall table not found")
	}
	c := &compatEmitter{sink: log.Log(), nameMap: nameMap}

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
	if us, ok := msg.(*spb.UnimplementedSyscall); ok {
		regs := us.Registers.GetArch().(*rpb.Registers_Amd64).Amd64
		sysnr := regs.OrigRax
		c.sink.Infof("Unsupported syscall: %s, regs: %+v", c.nameMap.Name(uintptr(sysnr)), regs)
	}
	return false, nil
}

// Close implements eventchannel.Emitter.
func (c *compatEmitter) Close() error {
	c.sink = nil
	return nil
}
