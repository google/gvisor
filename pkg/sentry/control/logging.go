// Copyright 2019 The gVisor Authors.
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

package control

import (
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/strace"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
)

// LoggingArgs are the arguments to use for changing the logging
// level and strace list.
type LoggingArgs struct {
	// SetLevel is a flag used to indicate that we should update
	// the logging level. We should be able to change the strace
	// list without affecting the logging level and vice versa.
	SetLevel bool

	// Level is the log level that will be set if SetLevel is true.
	Level log.Level

	// SetLogPackets indicates that we should update the log packets flag.
	SetLogPackets bool

	// LogPackets is the actual value to set for LogPackets.
	// SetLogPackets must be enabled to indicate that we're changing
	// the value.
	LogPackets bool

	// SetStrace is a flag used to indicate that strace related
	// arguments were passed in.
	SetStrace bool

	// EnableStrace is a flag from the CLI that specifies whether to
	// enable strace at all. If this flag is false then a completely
	// pristine copy of the syscall table will be swapped in. This
	// approach is used to remain consistent with an empty strace
	// whitelist meaning trace all system calls.
	EnableStrace bool

	// Strace is the whitelist of syscalls to trace to log. If this
	// and StraceEventWhitelist are empty trace all system calls.
	StraceWhitelist []string

	// SetEventStrace is a flag used to indicate that event strace
	// related arguments were passed in.
	SetEventStrace bool

	// StraceEventWhitelist is the whitelist of syscalls to trace
	// to event log.
	StraceEventWhitelist []string
}

// Logging provides functions related to logging.
type Logging struct{}

// Change will change the log level and strace arguments. Although
// this functions signature requires an error it never actually
// returns an error. It's required by the URPC interface.
// Additionally, it may look odd that this is the only method
// attached to an empty struct but this is also part of how
// URPC dispatches.
func (l *Logging) Change(args *LoggingArgs, code *int) error {
	if args.SetLevel {
		// Logging uses an atomic for the level so this is thread safe.
		log.SetLevel(args.Level)
	}

	if args.SetLogPackets {
		if args.LogPackets {
			atomic.StoreUint32(&sniffer.LogPackets, 1)
		} else {
			atomic.StoreUint32(&sniffer.LogPackets, 0)
		}
		log.Infof("LogPackets set to: %v", atomic.LoadUint32(&sniffer.LogPackets))
	}

	if args.SetStrace {
		if err := l.configureStrace(args); err != nil {
			return fmt.Errorf("error configuring strace: %v", err)
		}
	}

	if args.SetEventStrace {
		if err := l.configureEventStrace(args); err != nil {
			return fmt.Errorf("error configuring event strace: %v", err)
		}
	}

	return nil
}

func (l *Logging) configureStrace(args *LoggingArgs) error {
	if args.EnableStrace {
		// Install the whitelist specified.
		if len(args.StraceWhitelist) > 0 {
			if err := strace.Enable(args.StraceWhitelist, strace.SinkTypeLog); err != nil {
				return err
			}
		} else {
			// For convenience, if strace is enabled but whitelist
			// is empty, enable everything to log.
			strace.EnableAll(strace.SinkTypeLog)
		}
	} else {
		// Uninstall all strace functions.
		strace.Disable(strace.SinkTypeLog)
	}
	return nil
}

func (l *Logging) configureEventStrace(args *LoggingArgs) error {
	if len(args.StraceEventWhitelist) > 0 {
		if err := strace.Enable(args.StraceEventWhitelist, strace.SinkTypeEvent); err != nil {
			return err
		}
	} else {
		strace.Disable(strace.SinkTypeEvent)
	}
	return nil
}
