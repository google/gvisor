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
func (evs *Events) Execute(ctx context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	c, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
	if err != nil {
		Fatalf("loading sandbox: %v", err)
	}

	// Repeatedly get stats from the container.
	for {
		// Get the event and print it as JSON.
		ev, err := c.Event()
		if err != nil {
			log.Warningf("Error getting events for container: %v", err)
			if evs.stats {
				return subcommands.ExitFailure
			}
		}
		log.Debugf("Events: %+v", ev)

		// err must be preserved because it is used below when breaking
		// out of the loop.
		b, err := json.Marshal(ev)
		if err != nil {
			log.Warningf("Error while marshalling event %v: %v", ev, err)
		} else {
			os.Stdout.Write(b)
		}

		// If we're only running once, break. If we're only running
		// once and there was an error, the command failed.
		if evs.stats {
			if err != nil {
				return subcommands.ExitFailure
			}
			return subcommands.ExitSuccess
		}

		time.Sleep(time.Duration(evs.intervalSec) * time.Second)
	}
}
