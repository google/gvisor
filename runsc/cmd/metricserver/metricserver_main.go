// Copyright 2023 The gVisor Authors.
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

// The metricserver binary is a separate binary that implements the
// 'runsc metric-server' subcommand.
package main

import (
	"context"
	"os"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/cmd/metricserver/metricservercmd"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/metricserver"
)

// cmd implements subcommands.Command for the "metric-server" command.
type cmd struct {
	metricservercmd.Cmd
}

// Execute implements subcommands.Command.Execute.
func (c *cmd) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	conf, err := config.NewFromFlags(flag.CommandLine)
	if err != nil {
		util.Fatalf(err.Error())
	}
	if conf.MetricServer == "" || conf.RootDir == "" {
		flag.CommandLine.Usage()
		return subcommands.ExitUsageError
	}
	server := metricserver.Server{
		Config:                 conf,
		PIDFile:                c.Cmd.PIDFile,
		ExporterPrefix:         c.Cmd.ExporterPrefix,
		ExposeProfileEndpoints: c.Cmd.ExposeProfileEndpoints,
		AllowUnknownRoot:       c.Cmd.AllowUnknownRoot,
	}
	if err := server.Run(ctx); err != nil {
		return util.Errorf("%v", err)
	}
	return subcommands.ExitSuccess
}

func main() {
	subcommands.Register(&cmd{}, "metrics")
	config.RegisterFlags(flag.CommandLine)
	flag.Parse()
	subcmdCode := subcommands.Execute(context.Background())
	if subcmdCode == subcommands.ExitSuccess {
		os.Exit(0)
	}
	log.Warningf("Failure to execute command, err: %v", subcmdCode)
	os.Exit(128)
}
