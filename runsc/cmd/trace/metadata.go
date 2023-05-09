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

package trace

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	"gvisor.dev/gvisor/runsc/flag"
)

// metadata implements subcommands.Command for the "metadata" command.
type metadata struct{}

// Name implements subcommands.Command.
func (*metadata) Name() string {
	return "metadata"
}

// Synopsis implements subcommands.Command.
func (*metadata) Synopsis() string {
	return "list all trace points configuration information"
}

// Usage implements subcommands.Command.
func (*metadata) Usage() string {
	return `metadata - list all trace points configuration information
`
}

// SetFlags implements subcommands.Command.
func (*metadata) SetFlags(*flag.FlagSet) {}

// Execute implements subcommands.Command.
func (l *metadata) Execute(context.Context, *flag.FlagSet, ...any) subcommands.ExitStatus {
	// Sort to keep related points together.
	points := make([]seccheck.PointDesc, 0, len(seccheck.Points))
	for _, pt := range seccheck.Points {
		points = append(points, pt)
	}
	sort.Slice(points, func(i int, j int) bool {
		return points[i].Name < points[j].Name
	})

	fmt.Printf("POINTS (%d)\n", len(seccheck.Points))
	for _, pt := range points {
		optFields := fieldNames(pt.OptionalFields)
		ctxFields := fieldNames(pt.ContextFields)
		fmt.Printf("Name: %s, optional fields: [%s], context fields: [%s]\n", pt.Name, strings.Join(optFields, "|"), strings.Join(ctxFields, "|"))
	}
	fmt.Printf("\nSINKS (%d)\n", len(seccheck.Sinks))
	for _, sink := range seccheck.Sinks {
		fmt.Printf("Name: %s\n", sink.Name)
	}

	return subcommands.ExitSuccess
}

func fieldNames(fields []seccheck.FieldDesc) []string {
	names := make([]string, 0, len(fields))
	for _, f := range fields {
		names = append(names, f.Name)
	}
	return names
}
