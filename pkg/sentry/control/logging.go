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

	"gvisor.dev/gvisor/pkg/control/api"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/strace"
	"gvisor.dev/gvisor/pkg/tcpip/link/sniffer"
)

// LoggingArgs are the arguments to use for changing the logging
// level and strace list.
type LoggingArgs = api.LoggingArgs

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
			sniffer.LogPackets.Store(1)
		} else {
			sniffer.LogPackets.Store(0)
		}
		log.Infof("LogPackets set to: %v", sniffer.LogPackets.Load())
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
		// Install the allowlist specified.
		if len(args.StraceAllowlist) > 0 {
			if err := strace.Enable(args.StraceAllowlist, strace.SinkTypeLog); err != nil {
				return err
			}
		} else {
			// For convenience, if strace is enabled but allowlist
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
	if len(args.StraceEventAllowlist) > 0 {
		if err := strace.Enable(args.StraceEventAllowlist, strace.SinkTypeEvent); err != nil {
			return err
		}
	} else {
		strace.Disable(strace.SinkTypeEvent)
	}
	return nil
}
