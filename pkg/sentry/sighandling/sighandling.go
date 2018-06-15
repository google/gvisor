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

// forwardSignals listens for incoming signals and delivers them to k. It starts
// when the start channel is closed and stops when the stop channel is closed.
func forwardSignals(k *kernel.Kernel, sigchans []chan os.Signal, start, stop chan struct{}) {
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
				if started {
					// stop channel
					break
				} else {
					// start channel
					started = true
					sc[0] = reflect.SelectCase{Dir: reflect.SelectRecv, Chan: reflect.ValueOf(stop)}
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
		if !started || !k.SendExternalSignal(&arch.SignalInfo{Signo: int32(index)}, "sentry") {
			// Kernel is not ready to receive signals.
			//
			// Kill ourselves if this signal would have killed the
			// process before PrepareForwarding was called. i.e., all
			// _SigKill signals; see Go
			// src/runtime/sigtab_linux_generic.go.
			//
			// Otherwise ignore the signal.
			//
			// TODO: Convert Go's runtime.raise from
			// tkill to tgkill so PrepareForwarding doesn't need to
			// be called until after filter installation.
			switch linux.Signal(index) {
			case linux.SIGHUP, linux.SIGINT, linux.SIGTERM:
				dieFromSignal(linux.Signal(index))
			}
		}
	}

	// Close all individual channels.
	for _, sigchan := range sigchans {
		signal.Stop(sigchan)
		close(sigchan)
	}
}

// PrepareForwarding ensures that synchronous signals are forwarded to k and
// returns a callback that starts signal delivery, which itself returns a
// callback that stops signal forwarding.
func PrepareForwarding(k *kernel.Kernel) func() func() {
	start := make(chan struct{})
	stop := make(chan struct{})

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

		// SignalPanic is handled by Run.
		if linux.Signal(sig) == kernel.SignalPanic {
			continue
		}

		signal.Notify(sigchan, syscall.Signal(sig))
	}
	// Start up our listener.
	go forwardSignals(k, sigchans, start, stop) // S/R-SAFE: synchronized by Kernel.extMu

	return func() func() {
		close(start)
		return func() {
			close(stop)
		}
	}
}

// StartForwarding ensures that synchronous signals are forwarded to k and
// returns a callback that stops signal forwarding.
func StartForwarding(k *kernel.Kernel) func() {
	return PrepareForwarding(k)()
}
