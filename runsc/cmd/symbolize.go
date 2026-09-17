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

package cmd

import (
	"context"
	"os"

	"github.com/google/subcommands"

	"gvisor.dev/gvisor/pkg/coverage"
	"gvisor.dev/gvisor/runsc/cmd/sentry/sentrycmd"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/runsc/gvisorbinaries"
)

// Symbolize implements subcommands.Command for the "symbolize" command.
type Symbolize struct {
	sentrycmd.Symbolize
}

// Execute implements subcommands.Command.Execute.
func (c *Symbolize) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if f.NArg() != 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	sentry := &gvisorbinaries.GvisorSentry
	p, err := sentry.Path()
	if err != nil {
		// TODO(gvisor.dev/issues/13718): Remove this branch once sidecars are required
		if !coverage.Available() {
			return util.Errorf("symbolize requires coverage-instrumented gVisor binaries: Sentry sidecar binary %q is not available (%v) and this runsc binary was not built with coverage.", sentry.Name, err)
		}
		return c.Symbolize.Execute(ctx, f, args...)
	}
	argv := []string{p, c.Name()}
	if c.DumpAll {
		argv = append(argv, "-all")
	}
	err = sentry.Exec(gvisorbinaries.Options{Argv: argv, Envv: os.Environ()})
	// Unreachable unless `sentry.Exec` fails.
	return util.Errorf("Failed to execute %v: %v", argv, err)
}
