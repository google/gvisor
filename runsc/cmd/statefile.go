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
	"fmt"
	"os"

	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/state/pretty"
	"gvisor.dev/gvisor/pkg/state/statefile"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/flag"
)

// Statefile implements subcommands.Command for the "statefile" command.
type Statefile struct {
	list   bool
	get    string
	key    string
	output string
	html   bool
}

// Name implements subcommands.Command.
func (*Statefile) Name() string {
	return "state"
}

// Synopsis implements subcommands.Command.
func (*Statefile) Synopsis() string {
	return "shows information about a statefile"
}

// Usage implements subcommands.Command.
func (*Statefile) Usage() string {
	return `statefile [flags] <statefile>`
}

// SetFlags implements subcommands.Command.
func (s *Statefile) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&s.list, "list", false, "lists the metdata in the statefile.")
	f.StringVar(&s.get, "get", "", "extracts the given metadata key.")
	f.StringVar(&s.key, "key", "", "the integrity key for the file.")
	f.StringVar(&s.output, "output", "", "target to write the result.")
	f.BoolVar(&s.html, "html", false, "outputs in HTML format.")
}

// Execute implements subcommands.Command.Execute.
func (s *Statefile) Execute(_ context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	// Check arguments.
	if s.list && s.get != "" {
		util.Fatalf("error: can't specify -list and -get simultaneously.")
	}

	// Setup output.
	var output = os.Stdout // Default.
	if s.output != "" {
		f, err := os.OpenFile(s.output, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
		if err != nil {
			util.Fatalf("error opening output: %v", err)
		}
		defer func() {
			if err := f.Close(); err != nil {
				util.Fatalf("error flushing output: %v", err)
			}
		}()
		output = f
	}

	// Open the file.
	if f.NArg() != 1 {
		f.Usage()
		return subcommands.ExitUsageError
	}
	input, err := os.Open(f.Arg(0))
	if err != nil {
		util.Fatalf("error opening input: %v\n", err)
	}

	if s.html {
		fmt.Fprintf(output, "<html><body>\n")
		defer fmt.Fprintf(output, "</body></html>\n")
	}

	// Dump the full file?
	if !s.list && s.get == "" {
		var key []byte
		if s.key != "" {
			key = []byte(s.key)
		}
		rc, _, err := statefile.NewReader(input, key)
		if err != nil {
			util.Fatalf("error parsing statefile: %v", err)
		}
		if s.html {
			if err := pretty.PrintHTML(output, rc); err != nil {
				util.Fatalf("error printing state: %v", err)
			}
		} else {
			if err := pretty.PrintText(output, rc); err != nil {
				util.Fatalf("error printing state: %v", err)
			}
		}
		return subcommands.ExitSuccess
	}

	// Load just the metadata.
	metadata, err := statefile.MetadataUnsafe(input)
	if err != nil {
		util.Fatalf("error reading metadata: %v", err)
	}

	// Is it a single key?
	if s.get != "" {
		val, ok := metadata[s.get]
		if !ok {
			util.Fatalf("metadata key %s: not found", s.get)
		}
		fmt.Fprintf(output, "%s\n", val)
		return subcommands.ExitSuccess
	}

	// List all keys.
	if s.html {
		fmt.Fprintf(output, " <ul>\n")
		defer fmt.Fprintf(output, " </ul>\n")
	}
	for key := range metadata {
		if s.html {
			fmt.Fprintf(output, "  <li>%s</li>\n", key)
		} else {
			fmt.Fprintf(output, "%s\n", key)
		}
	}
	return subcommands.ExitSuccess
}
