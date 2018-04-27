// Copyright 2018 Google Inc.
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
	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/log"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/platform"
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
// Returns false if signal could not be sent because the Kernel is not fully
// initialized yet.
func (k *Kernel) sendExternalSignal(info *arch.SignalInfo, context string) bool {
	switch linux.Signal(info.Signo) {
	case platform.SignalInterrupt:
		// Assume that a call to platform.Context.Interrupt() misfired.
		return true

	case SignalPanic:
		// SignalPanic is also specially handled in sentry setup to ensure that
		// it causes a panic even after tasks exit, but SignalPanic may also
		// be sent here if it is received while in app context.
		panic("Signal-induced panic")

	default:
		log.Infof("Received external signal %d in %s context", info.Signo, context)
		if k.globalInit == nil {
			log.Warningf("Received external signal %d before init created", info.Signo)
			return false
		}
		k.globalInit.SendSignal(info)
	}

	return true
}

// sigPriv returns a SignalInfo representing a signal sent by the sentry. (The
// name reflects its equivalence to Linux's SEND_SIG_PRIV.)
func sigPriv(sig linux.Signal) *arch.SignalInfo {
	return &arch.SignalInfo{
		Signo: int32(sig),
		Code:  arch.SignalInfoKernel,
	}
}
