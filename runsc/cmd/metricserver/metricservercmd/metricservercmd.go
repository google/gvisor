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

// Package metricservercmd partially implements the 'metric-server' subcommand.
package metricservercmd

import (
	"gvisor.dev/gvisor/runsc/flag"
)

// Cmd partially implements subcommands.Command for the metric-server command.
type Cmd struct {
	ExporterPrefix         string
	PIDFile                string
	ExposeProfileEndpoints bool
	AllowUnknownRoot       bool
}

// Name implements subcommands.Command.Name.
func (*Cmd) Name() string {
	return "metric-server"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Cmd) Synopsis() string {
	return "implements Prometheus metrics HTTP endpoint"
}

// Usage implements subcommands.Command.Usage.
func (*Cmd) Usage() string {
	return `-root=<root dir> -metric-server=<addr> metric-server [-exporter-prefix=<runsc_>]
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (c *Cmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&c.ExporterPrefix, "exporter-prefix", "runsc_", "Prefix for all metric names, following Prometheus exporter convention")
	f.StringVar(&c.PIDFile, "pid-file", "", "If set, write the metric server's own PID to this file after binding to the --metric-server address. The parent directory of this file must already exist.")
	f.BoolVar(&c.ExposeProfileEndpoints, "allow-profiling", false, "If true, expose /runsc-metrics/profile-cpu and /runsc-metrics/profile-heap to get profiling data about the metric server")
	f.BoolVar(&c.AllowUnknownRoot, "allow-unknown-root", false, "if set, the metric server will keep running regardless of the existence of --root or the metric server's ability to access it.")
}
