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

// Package sighandling contains helpers for handling signals to applications.
package sighandling

import (
	"fmt"
	"os"
	"os/signal"
	"reflect"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/sentry/arch"
	"gvisor.googlesource.com/gvisor/pkg/sentry/kernel"
)

// numSignals is the number of normal (non-realtime) signals on Linux.
const numSignals = 32

// forwardSignals listens for incoming signals and delivers them to k.
//
// It starts when the start channel is closed, stops when the stop channel
// is closed, and closes done once it will no longer deliver signals to k.
func forwardSignals(k *kernel.Kernel, sigchans []chan os.Signal, start, stop, done chan struct{}) {
	// Build a select case.
	sc := []reflect.SelectCase{{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(start)}}
	for _, sigchan := range sigchans {
		sc = append(sc, reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(sigchan)})
	}

	started := false
	for {
		// Wait for a notification.
		index, _, ok := reflect.Select(sc)

		// Was it the start / stop channel?
		if index == 0 {
			if !ok {
				if !started {
					// start channel; start forwarding and
					// swap this case for the stop channel
					// to select stop requests.
					started = true
					sc[0] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(stop)}
				} else {
					// stop channel; stop forwarding and
					// clear this case so it is never
					// selected again.
					started = false
					close(done)
					sc[0].Chan = reflect.Value{}
				}
			}
			continue
		}

		// How about a different close?
		if !ok {
			panic("signal channel closed unexpectedly")
		}

		// Otherwise, it was a signal on channel N. Index 0 represents the stop
		// channel, so index N represents the channel for signal N.
		signal := linux.Signal(index)

		if !started {
			// Kernel cannot receive signals, either because it is
			// not ready yet or is shutting down.
			//
			// Kill ourselves if this signal would have killed the
			// process before PrepareForwarding was called. i.e., all
			// _SigKill signals; see Go
			// src/runtime/sigtab_linux_generic.go.
			//
			// Otherwise ignore the signal.
			//
			// TODO: Drop in Go 1.12, which uses tgkill
			// in runtime.raise.
			switch signal {
			case linux.SIGHUP, linux.SIGINT, linux.SIGTERM:
				dieFromSignal(signal)
				panic(fmt.Sprintf("Failed to die from signal %d", signal))
			default:
				continue
			}
		}

		k.SendExternalSignal(&arch.SignalInfo{Signo: int32(signal)}, "sentry")
	}
}

// PrepareForwarding ensures that synchronous signals are forwarded to k and
// returns a callback that starts signal delivery, which itself returns a
// callback that stops signal forwarding.
//
// Note that this function permanently takes over signal handling. After the
// stop callback, signals revert to the default Go runtime behavior, which
// cannot be overridden with external calls to signal.Notify.
func PrepareForwarding(k *kernel.Kernel, skipSignal syscall.Signal) func() func() {
	start := make(chan struct{})
	stop := make(chan struct{})
	done := make(chan struct{})

	// Register individual channels. One channel per standard signal is
	// required as os.Notify() is non-blocking and may drop signals. To avoid
	// this, standard signals have to be queued separately. Channel size 1 is
	// enough for standard signals as their semantics allow de-duplication.
	//
	// External real-time signals are not supported. We rely on the go-runtime
	// for their handling.
	var sigchans []chan os.Signal
	for sig := 1; sig <= numSignals+1; sig++ {
		sigchan := make(chan os.Signal, 1)
		sigchans = append(sigchans, sigchan)

		if syscall.Signal(sig) == skipSignal {
			continue
		}

		signal.Notify(sigchan, syscall.Signal(sig))
	}
	// Start up our listener.
	go forwardSignals(k, sigchans, start, stop, done) // S/R-SAFE: synchronized by Kernel.extMu.

	return func() func() {
		close(start)
		return func() {
			close(stop)
			<-done
		}
	}
}
