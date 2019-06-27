// Copyright 2019 The gVisor Authors.
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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"text/tabwriter"

	"flag"
	"github.com/google/subcommands"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
)

// Syscalls implements subcommands.Command for the "syscalls" command.
type Syscalls struct {
	output string
	os     string
	arch   string
}

// CompatibilityInfo is a map of system and architecture to compatibility doc.
// Maps operating system to architecture to ArchInfo.
type CompatibilityInfo map[string]map[string]ArchInfo

// ArchInfo is compatibility doc for an architecture.
type ArchInfo struct {
	// Syscalls maps syscall number for the architecture to the doc.
	Syscalls map[uintptr]SyscallDoc `json:"syscalls"`
}

// SyscallDoc represents a single item of syscall documentation.
type SyscallDoc struct {
	Name string `json:"name"`
	num  uintptr

	Support string   `json:"support"`
	Note    string   `json:"note,omitempty"`
	URLs    []string `json:"urls,omitempty"`
}

type outputFunc func(io.Writer, CompatibilityInfo) error

var (
	// The string name to use for printing compatibility for all OSes.
	osAll = "all"

	// The string name to use for printing compatibility for all architectures.
	archAll = "all"

	// A map of OS name to map of architecture name to syscall table.
	syscallTableMap = make(map[string]map[string]*kernel.SyscallTable)

	// A map of output type names to output functions.
	outputMap = map[string]outputFunc{
		"table": outputTable,
		"json":  outputJSON,
		"csv":   outputCSV,
	}
)

// Name implements subcommands.Command.Name.
func (*Syscalls) Name() string {
	return "syscalls"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*Syscalls) Synopsis() string {
	return "Print compatibility information for syscalls."
}

// Usage implements subcommands.Command.Usage.
func (*Syscalls) Usage() string {
	return `syscalls [options] - Print compatibility information for syscalls.
`
}

// SetFlags implements subcommands.Command.SetFlags.
func (s *Syscalls) SetFlags(f *flag.FlagSet) {
	f.StringVar(&s.output, "o", "table", "Output format (table, csv, json).")
	f.StringVar(&s.os, "os", osAll, "The OS (e.g. linux)")
	f.StringVar(&s.arch, "arch", archAll, "The CPU architecture (e.g. amd64).")
}

// Execute implements subcommands.Command.Execute.
func (s *Syscalls) Execute(_ context.Context, f *flag.FlagSet, args ...interface{}) subcommands.ExitStatus {
	out, ok := outputMap[s.output]
	if !ok {
		Fatalf("Unsupported output format %q", s.output)
	}

	// Build map of all supported architectures.
	tables := kernel.SyscallTables()
	for _, t := range tables {
		osMap, ok := syscallTableMap[t.OS.String()]
		if !ok {
			osMap = make(map[string]*kernel.SyscallTable)
			syscallTableMap[t.OS.String()] = osMap
		}
		osMap[t.Arch.String()] = t
	}

	// Build a map of the architectures we want to output.
	info, err := getCompatibilityInfo(s.os, s.arch)
	if err != nil {
		Fatalf("%v", err)
	}

	if err := out(os.Stdout, info); err != nil {
		Fatalf("Error writing output: %v", err)
	}

	return subcommands.ExitSuccess
}

// getCompatibilityInfo returns compatibility info for the given OS name and
// architecture name. Supports the special name 'all' for OS and architecture that
// specifies that all supported OSes or architectures should be included.
func getCompatibilityInfo(osName string, archName string) (CompatibilityInfo, error) {
	info := CompatibilityInfo(make(map[string]map[string]ArchInfo))
	if osName == osAll {
		// Special processing for the 'all' OS name.
		for osName, _ := range syscallTableMap {
			info[osName] = make(map[string]ArchInfo)
			// osName is a specific OS name.
			if err := addToCompatibilityInfo(info, osName, archName); err != nil {
				return info, err
			}
		}
	} else {
		// osName is a specific OS name.
		info[osName] = make(map[string]ArchInfo)
		if err := addToCompatibilityInfo(info, osName, archName); err != nil {
			return info, err
		}
	}

	return info, nil
}

// addToCompatibilityInfo adds ArchInfo for the given specific OS name and
// architecture name. Supports the special architecture name 'all' to specify
// that all supported architectures for the OS should be included.
func addToCompatibilityInfo(info CompatibilityInfo, osName string, archName string) error {
	if archName == archAll {
		// Special processing for the 'all' architecture name.
		for archName, _ := range syscallTableMap[osName] {
			archInfo, err := getArchInfo(osName, archName)
			if err != nil {
				return err
			}
			info[osName][archName] = archInfo
		}
	} else {
		// archName is a specific architecture name.
		archInfo, err := getArchInfo(osName, archName)
		if err != nil {
			return err
		}
		info[osName][archName] = archInfo
	}

	return nil
}

// getArchInfo returns compatibility info for a specific OS and architecture.
func getArchInfo(osName string, archName string) (ArchInfo, error) {
	info := ArchInfo{}
	info.Syscalls = make(map[uintptr]SyscallDoc)

	t, ok := syscallTableMap[osName][archName]
	if !ok {
		return info, fmt.Errorf("syscall table for %s/%s not found", osName, archName)
	}

	for num, sc := range t.Table {
		info.Syscalls[num] = SyscallDoc{
			Name:    sc.Name,
			num:     num,
			Support: sc.SupportLevel.String(),
			Note:    sc.Note,
			URLs:    sc.URLs,
		}
	}

	return info, nil
}

// outputTable outputs the syscall info in tabular format.
func outputTable(w io.Writer, info CompatibilityInfo) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	// Linux
	for osName, osInfo := range info {
		for archName, archInfo := range osInfo {
			// Print the OS/arch
			fmt.Fprintf(w, "%s/%s:\n\n", osName, archName)

			// Sort the syscalls for output in the table.
			sortedCalls := []SyscallDoc{}
			for _, sc := range archInfo.Syscalls {
				sortedCalls = append(sortedCalls, sc)
			}
			sort.Slice(sortedCalls, func(i, j int) bool {
				return sortedCalls[i].num < sortedCalls[j].num
			})

			// Write the header
			_, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
				"NUM",
				"NAME",
				"SUPPORT",
				"NOTE",
			)
			if err != nil {
				return err
			}

			// Write each syscall entry
			for _, sc := range sortedCalls {
				_, err = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n",
					strconv.FormatInt(int64(sc.num), 10),
					sc.Name,
					sc.Support,
					sc.Note,
				)
				if err != nil {
					return err
				}
				// Add issue urls to note.
				for _, url := range sc.URLs {
					_, err = fmt.Fprintf(tw, "%s\t%s\t%s\tSee: %s\t\n",
						"",
						"",
						"",
						url,
					)
					if err != nil {
						return err
					}
				}
			}

			err = tw.Flush()
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// outputJSON outputs the syscall info in JSON format.
func outputJSON(w io.Writer, info CompatibilityInfo) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(info)
}

// numberedRow is aCSV row annotated by syscall number (used for sorting)
type numberedRow struct {
	num uintptr
	row []string
}

// outputCSV outputs the syscall info in tabular format.
func outputCSV(w io.Writer, info CompatibilityInfo) error {
	csvWriter := csv.NewWriter(w)

	// Linux
	for osName, osInfo := range info {
		for archName, archInfo := range osInfo {
			// Sort the syscalls for output in the table.
			sortedCalls := []numberedRow{}
			for _, sc := range archInfo.Syscalls {
				// Add issue urls to note.
				note := sc.Note
				for _, url := range sc.URLs {
					note = fmt.Sprintf("%s\nSee: %s", note, url)
				}

				sortedCalls = append(sortedCalls, numberedRow{
					num: sc.num,
					row: []string{
						osName,
						archName,
						strconv.FormatInt(int64(sc.num), 10),
						sc.Name,
						sc.Support,
						note,
					},
				})
			}
			sort.Slice(sortedCalls, func(i, j int) bool {
				return sortedCalls[i].num < sortedCalls[j].num
			})

			// Write the header
			err := csvWriter.Write([]string{
				"OS",
				"Arch",
				"Num",
				"Name",
				"Support",
				"Note",
			})
			if err != nil {
				return err
			}

			// Write each syscall entry
			for _, sc := range sortedCalls {
				err = csvWriter.Write(sc.row)
				if err != nil {
					return err
				}
			}

			csvWriter.Flush()
			err = csvWriter.Error()
			if err != nil {
				return err
			}
		}
	}

	return nil
}
