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
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/metricserver"
)

// Main returns the status code of the metric server.
func Main() subcommands.ExitStatus {
	ctx := context.Background()
	config.RegisterFlags(flag.CommandLine)
	server := metricserver.Server{}
	flag.CommandLine.StringVar(&server.ExporterPrefix, "metricserver-exporter-prefix", "runsc_", "Prefix for all metric names, following Prometheus exporter convention")
	flag.CommandLine.StringVar(&server.PIDFile, "metricserver-pid-file", "", "If set, write the metric server's own PID to this file after binding to the --metric-server address. The parent directory of this file must already exist.")
	flag.CommandLine.BoolVar(&server.ExposeProfileEndpoints, "metricserver-allow-profiling", false, "If true, expose /runsc-metrics/profile-cpu and /runsc-metrics/profile-heap to get profiling data about the metric server")
	flag.CommandLine.BoolVar(&server.AllowUnknownRoot, "metricserver-allow-unknown-root", false, "if set, the metric server will keep running regardless of the existence of --root or the metric server's ability to access it.")
	flag.Parse()
	if flag.CommandLine.NArg() != 0 {
		flag.CommandLine.Usage()
		return subcommands.ExitUsageError
	}
	conf, err := config.NewFromFlags(flag.CommandLine)
	if err != nil {
		util.Fatalf(err.Error())
	}
	if conf.MetricServer == "" || conf.RootDir == "" {
		flag.CommandLine.Usage()
		return subcommands.ExitUsageError
	}
	server.Config = conf
	if err := server.Run(ctx); err != nil {
		return util.Errorf("%v", err)
	}
	return subcommands.ExitSuccess
}

func main() {
	os.Exit(int(Main()))
}
