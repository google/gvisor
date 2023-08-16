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
	"gvisor.dev/gvisor/pkg/prometheus"
	"gvisor.dev/gvisor/pkg/sentry/control"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/container"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/metricserver/containermetrics"
)

// MetricExport implements subcommands.Command for the "metric-export" command.
type MetricExport struct {
	exporterPrefix       string
	sandboxMetricsFilter string
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
	return `export-metrics [-exporter-prefix=<runsc_>] <container id> - prints sandbox metric data in Prometheus metric format
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (m *MetricExport) SetFlags(f *flag.FlagSet) {
	f.StringVar(&m.exporterPrefix, "exporter-prefix", "runsc_", "Prefix for all metric names, following Prometheus exporter convention")
	f.StringVar(&m.sandboxMetricsFilter, "sandbox-metrics-filter", "", "If set, filter exported metrics using the specified regular expression. This filtering is applied before adding --exporter-prefix.")
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

	prometheusLabels, err := containermetrics.SandboxPrometheusLabels(cont)
	if err != nil {
		util.Fatalf("Cannot compute Prometheus labels of sandbox: %v", err)
	}

	snapshot, err := cont.Sandbox.ExportMetrics(control.MetricsExportOpts{
		OnlyMetrics: m.sandboxMetricsFilter,
	})
	if err != nil {
		util.Fatalf("ExportMetrics failed: %v", err)
	}
	commentHeader := fmt.Sprintf("Command-line export for sandbox %s", cont.Sandbox.ID)
	if m.sandboxMetricsFilter != "" {
		commentHeader = fmt.Sprintf("%s (filtered using regular expression: %q)", commentHeader, m.sandboxMetricsFilter)
	}
	written, err := prometheus.Write(os.Stdout, prometheus.ExportOptions{
		CommentHeader: commentHeader,
	}, map[*prometheus.Snapshot]prometheus.SnapshotExportOptions{
		snapshot: {
			ExporterPrefix: m.exporterPrefix,
			ExtraLabels:    prometheusLabels,
		},
	})
	if err != nil {
		util.Fatalf("Cannot write metrics to stdout: %v", err)
	}
	util.Infof("Wrote %d bytes of Prometheus metric data to stdout", written)

	return subcommands.ExitSuccess
}
