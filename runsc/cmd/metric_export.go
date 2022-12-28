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
	"bufio"
	"context"
	"fmt"
	"os"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/prometheus"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
)

// MetricExport implements subcommands.Command for the "metric-export" command.
type MetricExport struct {
}

// Name implements subcommands.Command.Name.
func (*MetricExport) Name() string {
	return "export-metrics"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*MetricExport) Synopsis() string {
	return "export metric data for the sandbox"
}

// Usage implements subcommands.Command.Usage.
func (*MetricExport) Usage() string {
	return `export-metrics <container id> - prints sandbox metric data in Prometheus metric format`
}

// SetFlags implements subcommands.Command.SetFlags.
func (m *MetricExport) SetFlags(f *flag.FlagSet) {
}

// Execute implements subcommands.Command.Execute.
func (m *MetricExport) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() < 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	id := f.Arg(0)
	conf := args[0].(*config.Config)

	cont, err := container.Load(conf.RootDir, container.FullID{ContainerID: id}, container.LoadOpts{})
	if err != nil {
		util.Fatalf("loading container: %v", err)
	}

	snapshot, err := cont.Sandbox.ExportMetrics()
	if err != nil {
		util.Fatalf("ExportMetrics failed: %v", err)
	}
	bufWriter := bufio.NewWriter(os.Stdout)
	written, err := snapshot.WriteTo(bufWriter, prometheus.ExportOptions{
		CommentHeader:  fmt.Sprintf("Command-line export for sandbox %s owning container %s", cont.Sandbox.ID, id),
		ExporterPrefix: conf.MetricExporterPrefix,
		ExtraLabels: map[string]string{
			"sandbox":   cont.Sandbox.ID,
			"container": cont.ID,
		},
	})
	if err != nil {
		util.Fatalf("Cannot write metrics to stdout: %v", err)
	}
	if err = bufWriter.Flush(); err != nil {
		util.Fatalf("Cannot flush metrics to stdout: %v", err)
	}
	util.Infof("Wrote %d bytes of Prometheus metric data to stdout", written)

	return subcommands.ExitSuccess
}
