// Copyright 2020 The gVisor Authors.
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

package trace

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/runsc/boot"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// create implements subcommands.Command for the "create" command.
type create struct {
	config string
	force  bool
}

// Name implements subcommands.Command.
func (*create) Name() string {
	return "create"
}

// Synopsis implements subcommands.Command.
func (*create) Synopsis() string {
	return "create a trace session"
}

// Usage implements subcommands.Command.
func (*create) Usage() string {
	return `create [flags] <sandbox id> - create a trace session
`
}

// SetFlags implements subcommands.Command.
func (l *create) SetFlags(f *flag.FlagSet) {
	f.StringVar(&l.config, "config", "", "path to the JSON file that describes the session being created")
	f.BoolVar(&l.force, "force", false, "deletes a conflicting session, if one exists")
}

// Execute implements subcommands.Command.
func (l *create) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	if len(l.config) == 0 {
		f.Usage()
		return util.Errorf("missing path to configuration file, please set --config=[path]")
	}

	sessionConfig, err := decodeTraceConfig(l.config)
	if err != nil {
		return util.Errorf("loading config file: %v", err)
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	opts := container.LoadOpts{
		SkipCheck:     true,
		RootContainer: true,
	}
	c, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, opts)
	if err != nil {
		util.Fatalf("loading sandbox: %v", err)
	}

	if err := c.Sandbox.CreateTraceSession(sessionConfig, l.force); err != nil {
		util.Fatalf("creating session: %v", err)
	}

	fmt.Printf("Trace session %q created.\n", sessionConfig.Name)
	return subcommands.ExitSuccess
}

func decodeTraceConfig(path string) (*seccheck.SessionConfig, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	sessionConfig := &seccheck.SessionConfig{}
	err = decoder.Decode(sessionConfig)
	if err == nil {
		// Success, we're done.
		return sessionConfig, nil
	}

	// If file cannot be decoded as a SessionConfig, try with InitConfig as
	// convenience in case the caller wants to reuse a trace session from
	// InitConfig file.
	log.Debugf("Config file is not a seccheck.SessionConfig, try with boot.InitConfig instead: %v", err)
	if _, err := file.Seek(0, 0); err != nil {
		return nil, err
	}
	initConfig := &boot.InitConfig{}
	if err := decoder.Decode(initConfig); err != nil {
		return nil, fmt.Errorf("invalid configuration file: %w", err)
	}
	return &initConfig.TraceSession, nil
}
