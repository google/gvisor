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

package cmd

import (
	"context"
	"encoding/json"
	"os"
	"time"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// Events implements subcommands.Command for the "events" command.
type Events struct {
	// The interval between stats reporting.
	intervalSec int
	// If true, events will print a single group of stats and exit.
	stats bool
}

// Name implements subcommands.Command.Name.
func (*Events) Name() string {
	return "events"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Events) Synopsis() string {
	return "display container events such as OOM notifications, cpu, memory, and IO usage statistics"
}

// Usage implements subcommands.Command.Usage.
func (*Events) Usage() string {
	return `<container-id>

Where "<container-id>" is the name for the instance of the container.

The events command displays information about the container. By default the
information is displayed once every 5 seconds.

OPTIONS:
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (evs *Events) SetFlags(f *flag.FlagSet) {
	f.IntVar(&evs.intervalSec, "interval", 5, "set the stats collection interval, in seconds")
	f.BoolVar(&evs.stats, "stats", false, "display the container's stats then exit")
}

// Execute implements subcommands.Command.Execute.
func (evs *Events) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	c, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
	if err != nil {
		util.Fatalf("loading sandbox: %v", err)
	}

	if evs.stats {
		ev, err := c.Event()
		if err != nil {
			log.Warningf("Error getting events for container: %v", err)
			return subcommands.ExitFailure
		}
		log.Debugf("Events: %+v", ev)
		if err := json.NewEncoder(os.Stdout).Encode(ev.Event); err != nil {
			log.Warningf("Error encoding event %+v: %v", ev.Event, err)
			return subcommands.ExitFailure
		}
		return subcommands.ExitSuccess
	}

	oomNotif, err := c.Sandbox.NotifyOOM()
	if err != nil {
		util.Fatalf("notifying on OOM: %v", err)
	}

	t := time.NewTicker(time.Duration(evs.intervalSec) * time.Second)
	for {
		var ev *boot.EventOut
		var err error
		select {
		case <-t.C:
			ev, err = c.Event()
		case _, ok := <-oomNotif:
			if ok {
				ev = &boot.EventOut{Event: boot.Event{Type: "oom", ID: id}}
			} else {
				oomNotif = nil
			}
			err = nil
		}
		if err != nil {
			log.Warningf("Error getting events for container: %v", err)
			continue
		}

		log.Debugf("Events: %+v", ev)
		if err := json.NewEncoder(os.Stdout).Encode(ev.Event); err != nil {
			log.Warningf("Error encoding event %+v: %v", ev.Event, err)
			continue
		}
		// If the OOM notification channel is closed the container and its cgroups
		// have been destroyed.
		if oomNotif == nil {
			break
		}
	}
	return subcommands.ExitSuccess
}
