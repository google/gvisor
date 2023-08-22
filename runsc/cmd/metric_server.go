// Copyright 2022 The gVisor Authors.
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
	"fmt"
	"os"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/runsc/cmd/metricserver"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

// MetricServer implements subcommands.Command for the "metric-server" command.
type MetricServer struct {
	ExporterPrefix         string
	PIDFile                string
	ExposeProfileEndpoints bool
	AllowUnknownRoot       bool
}

// Name implements subcommands.Command.Name.
func (*MetricServer) Name() string {
	return "metric-server"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*MetricServer) Synopsis() string {
	return "implements Prometheus metrics HTTP endpoint"
}

// Usage implements subcommands.Command.Usage.
func (*MetricServer) Usage() string {
	return `-root=<root dir> -metric-server=<addr> metric-server [-exporter-prefix=<runsc_>]
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (m *MetricServer) SetFlags(f *flag.FlagSet) {
	f.StringVar(&m.ExporterPrefix, "exporter-prefix", "runsc_", "Prefix for all metric names, following Prometheus exporter convention")
	f.StringVar(&m.PIDFile, "pid-file", "", "If set, write the metric server's own PID to this file after binding to the --metric-server address. The parent directory of this file must already exist.")
	f.BoolVar(&m.ExposeProfileEndpoints, "allow-profiling", false, "If true, expose /runsc-metrics/profile-cpu and /runsc-metrics/profile-heap to get profiling data about the metric server")
	f.BoolVar(&m.AllowUnknownRoot, "allow-unknown-root", false, "if set, the metric server will keep running regardless of the existence of --root or the metric server's ability to access it.")
}

// Execute implements subcommands.Command.Execute.
func (m *MetricServer) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	var newArgs []string
	newArgs = append(newArgs, metricserver.BinaryName)
	newArgs = append(newArgs, args[0].(*config.Config).ToFlags()...)
	newArgs = append(newArgs,
		fmt.Sprintf("--metricserver-exporter-prefix=%s", m.ExporterPrefix),
		fmt.Sprintf("--metricserver-pid-file=%s", m.PIDFile),
		fmt.Sprintf("--metricserver-allow-profiling=%t", m.ExposeProfileEndpoints),
		fmt.Sprintf("--metricserver-allow-unknown-root=%t", m.AllowUnknownRoot),
	)
	err := metricserver.Exec(metricserver.Options{
		Argv: newArgs,
		Envv: os.Environ(),
	})
	if err != nil {
		util.Fatalf("metric server: %v", err)
	}
	util.Fatalf("unreachable")
	return subcommands.ExitFailure
}
