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

package cmd

import (
	"context"
	"fmt"

	"github.com/google/subcommands"
	"google.golang.org/protobuf/encoding/prototext"
	"gvisor.dev/gvisor/pkg/metric"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/flag"
)

// MetricMetadata implements subcommands.Command for the "metric-metadata" command.
type MetricMetadata struct {
}

// Name implements subcommands.Command.Name.
func (*MetricMetadata) Name() string {
	return "metric-metadata"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*MetricMetadata) Synopsis() string {
	return "export metric metadata of metrics registered in this build, in text proto format"
}

// Usage implements subcommands.Command.Usage.
func (*MetricMetadata) Usage() string {
	return "metric-metadata"
}

// SetFlags implements subcommands.Command.SetFlags.
func (m *MetricMetadata) SetFlags(f *flag.FlagSet) {
}

// Execute implements subcommands.Command.Execute.
func (m *MetricMetadata) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if err := metric.Initialize(); err != nil {
		util.Fatalf("Cannot initialize metrics: %v", err)
	}
	registration, err := metric.GetMetricRegistration()
	if err != nil {
		util.Fatalf("Cannot get metric registration data: %v", err)
	}
	fmt.Println(prototext.MarshalOptions{Multiline: true, EmitASCII: true}.Format(registration))
	return subcommands.ExitSuccess
}
