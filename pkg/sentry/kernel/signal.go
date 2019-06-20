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

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/platform"
)

// SignalPanic is used to panic the running threads. It is a signal which
// cannot be used by the application: it must be caught and ignored by the
// runtime (in order to catch possible races).
const SignalPanic = linux.SIGUSR2

// sendExternalSignal is called when an asynchronous signal is sent to the
// sentry ("in sentry context"). On some platforms, it may also be called when
// an asynchronous signal is sent to sandboxed application threads ("in
// application context").
//
// context is used only for debugging to differentiate these cases.
//
// Preconditions: Kernel must have an init process.
func (k *Kernel) sendExternalSignal(info *arch.SignalInfo, context string) {
	switch linux.Signal(info.Signo) {
	case platform.SignalInterrupt:
		// Assume that a call to platform.Context.Interrupt() misfired.

	case SignalPanic:
		// SignalPanic is also specially handled in sentry setup to ensure that
		// it causes a panic even after tasks exit, but SignalPanic may also
		// be sent here if it is received while in app context.
		panic("Signal-induced panic")

	default:
		log.Infof("Received external signal %d in %s context", info.Signo, context)
		if k.globalInit == nil {
			panic(fmt.Sprintf("Received external signal %d before init created", info.Signo))
		}
		k.globalInit.SendSignal(info)
	}
}

// SignalInfoPriv returns a SignalInfo equivalent to Linux's SEND_SIG_PRIV.
func SignalInfoPriv(sig linux.Signal) *arch.SignalInfo {
	return &arch.SignalInfo{
		Signo: int32(sig),
		Code:  arch.SignalInfoKernel,
	}
}

// SignalInfoNoInfo returns a SignalInfo equivalent to Linux's SEND_SIG_NOINFO.
func SignalInfoNoInfo(sig linux.Signal, sender, receiver *Task) *arch.SignalInfo {
	info := &arch.SignalInfo{
		Signo: int32(sig),
		Code:  arch.SignalInfoUser,
	}
	info.SetPid(int32(receiver.tg.pidns.IDOfThreadGroup(sender.tg)))
	info.SetUid(int32(sender.Credentials().RealKUID.In(receiver.UserNamespace()).OrOverflow()))
	return info
}
