// Copyright 2018 Google LLC
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

// This program will take a single golang source file, or a directory containing
// many source files and produce a JSON output which represent any comments
// containing compatibility metadata.

// Command parse-syscall-annotations parses syscall annotations from Godoc and
// generates a JSON file with the parsed syscall info.
//
// Annotations take the form:
// @Syscall(<name>, <arg>:<value>, ...)
//
// Supported args and values are:
// - arg: A syscall option. This entry only applies to the syscall when given this option.
// - support: Indicates support level
//   - FULL: Full support
//   - PARTIAL: Partial support. Details should be provided in note.
//   - UNIMPLEMENTED: Unimplemented
// - returns: Indicates a known return value. Implies PARTIAL support. Values are syscall errors.
//            This is treated as a string so you can use something like "returns:EPERM or ENOSYS".
// - issue: A GitHub issue number.
// - note: A note

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
)

var (
	srcDir  = flag.String("dir", "./", "The source directory")
	jsonOut = flag.Bool("json", false, "Output info as json")

	r  *regexp.Regexp
	r2 *regexp.Regexp

	mdTemplate = template.Must(template.New("name").Parse(`+++
title = "AMD64"
description = "Syscall Compatibility Reference Documentation for AMD64"
weight = 10
+++

This table is a reference of Linux syscalls for the AMD64 architecture and
their compatibility status in gVisor. gVisor does not support all syscalls and
some syscalls may have a partial implementation.

Of {{ .Total }} syscalls, {{ .Implemented }} syscalls have a full or partial
implementation. There are currently {{ .Unimplemented }} unimplemented
syscalls. {{ .Unknown }} syscalls are not yet documented.

<table>
  <thead>
    <tr>
      <th>#</th>
      <th>Name</th>
      <th>Support</th>
      <th>GitHub Issue</th>
      <th>Notes</th>
    </tr>
  </thead>
  <tbody>{{ range .Syscalls }}{{ if ne .Support "Unknown" }}
    <tr>
      <td><a class="doc-table-anchor" id="{{ .Name }}{{ if index .Metadata "arg" }}({{ index .Metadata "arg" }}){{ end }}"></a>{{ .Number }}</td>
      <td><a href="http://man7.org/linux/man-pages/man2/{{ .Name }}.2.html" target="_blank" rel="noopener">{{ .Name }}{{ if index .Metadata "arg" }}({{ index .Metadata "arg" }}){{ end }}</a></td>
      <td>{{ .Support }}</td>
      <td>{{ if index .Metadata "issue" }}<a href="https://github.com/google/gvisor/issues/{{ index .Metadata "issue" }}">#{{ index .Metadata "issue" }}</a>{{ end }}</td>
      <td>{{ .Note }}</td>
    </tr>{{ end }}{{ end }}
  </tbody>
</table>
`))
)

// Syscall represents a function implementation of a syscall.
type Syscall struct {
	File string
	Line int

	Number int
	Name   string

	Metadata map[string]string
}

const (
	UNKNOWN = iota
	UNIMPLEMENTED
	PARTIAL_SUPPORT
	FULL_SUPPORT
)

func (s *Syscall) SupportLevel() int {
	supportLevel := UNKNOWN
	switch strings.ToUpper(s.Metadata["support"]) {
	case "FULL":
		supportLevel = FULL_SUPPORT
	case "PARTIAL":
		supportLevel = PARTIAL_SUPPORT
	case "UNIMPLEMENTED":
		supportLevel = UNIMPLEMENTED
	}

	// If an arg or returns is specifed treat that as a partial implementation even if
	// there is full support for the argument.
	if s.Metadata["arg"] != "" {
		supportLevel = PARTIAL_SUPPORT
	}
	if s.Metadata["returns"] != "" && supportLevel == UNKNOWN {
		returns := strings.ToUpper(s.Metadata["returns"])
		// Default to PARTIAL support if only returns is specified
		supportLevel = PARTIAL_SUPPORT

		// If ENOSYS is returned unequivically, treat it as unimplemented.
		if returns == "ENOSYS" {
			supportLevel = UNIMPLEMENTED
		}
	}

	return supportLevel
}

func (s *Syscall) Support() string {
	l := s.SupportLevel()
	switch l {
	case FULL_SUPPORT:
		return "Full"
	case PARTIAL_SUPPORT:
		return "Partial"
	case UNIMPLEMENTED:
		return "Unimplemented"
	default:
		return "Unknown"
	}
}

func (s *Syscall) Note() string {
	note := s.Metadata["note"]
	returns := s.Metadata["returns"]
	// Add "Returns ENOSYS" note by default if support:UNIMPLEMENTED
	if returns == "" && s.SupportLevel() == UNIMPLEMENTED {
		returns = "ENOSYS"
	}
	if returns != "" {
		return_note := fmt.Sprintf("Returns %s", returns)
		if note != "" {
			note = return_note + "; " + note
		} else {
			note = return_note
		}
	}
	if note == "" && s.SupportLevel() == FULL_SUPPORT {
		note = "Full Support"
	}
	return note
}

type Report struct {
	Implemented   int
	Unimplemented int
	Unknown       int
	Total         int
	Syscalls      []*Syscall
}

func init() {
	// Build a regex that will attempt to match all fields in tokens.

	// Regexp for matching syscall definitions
	s := "@Syscall\\(([^\\),]+)([^\\)]+)\\)"
	r = regexp.MustCompile(s)

	// Regexp for matching metadata
	s2 := "([^\\ ),]+):([^\\),]+)"
	r2 = regexp.MustCompile(s2)

	ReverseSyscallMap = make(map[string]int)
	for no, name := range SyscallMap {
		ReverseSyscallMap[name] = no
	}
}

// parseDoc parses all comments in a file and returns the parsed syscall
// information.
func parseDoc(fs *token.FileSet, f *ast.File) []*Syscall {
	syscalls := []*Syscall{}
	for _, cg := range f.Comments {
		for _, line := range strings.Split(cg.Text(), "\n") {
			if syscall := parseLine(fs, line); syscall != nil {
				pos := fs.Position(cg.Pos())
				syscall.File = pos.Filename
				syscall.Line = pos.Line

				syscalls = append(syscalls, syscall)
			}
		}
	}
	return syscalls
}

// parseLine parses a single line of Godoc and returns the parsed syscall
// information. If no information is found, nil is returned.
// Syscall declarations take the form:
// @Syscall(<name>, <verb>:<value>, ...)
func parseLine(fs *token.FileSet, line string) *Syscall {
	s := r.FindAllStringSubmatch(line, -1)
	if len(s) > 0 {
		name := strings.ToLower(s[0][1])
		if n, ok := ReverseSyscallMap[name]; ok {
			syscall := Syscall{}
			syscall.Name = name
			syscall.Number = n
			syscall.Metadata = make(map[string]string)
			s2 := r2.FindAllStringSubmatch(s[0][2], -1)
			for _, match := range s2 {
				syscall.Metadata[match[1]] = match[2]
			}
			return &syscall
		} else {
			log.Printf("Warning: unknown syscall %q", name)
		}
	}
	return nil
}

func main() {
	flag.Parse()

	var syscalls []*Syscall

	err := filepath.Walk(*srcDir, func(path string, info os.FileInfo, err error) error {
		if info != nil && info.IsDir() {
			fs := token.NewFileSet()
			d, err := parser.ParseDir(fs, path, nil, parser.ParseComments)
			if err != nil {
				return err
			}

			for _, p := range d {
				for _, f := range p.Files {
					s := parseDoc(fs, f)
					syscalls = append(syscalls, s...)
				}
			}
		}

		return nil
	})

	if err != nil {
		fmt.Printf("failed to walk dir %s: %v", *srcDir, err)
		os.Exit(1)
	}

	var fullList []*Syscall
	for no, name := range SyscallMap {
		found := false
		for _, s := range syscalls {
			if s.Number == no {
				fullList = append(fullList, s)
				found = true
			}
		}
		if !found {
			fullList = append(fullList, &Syscall{
				Name:   name,
				Number: no,
			})
		}
	}

	// Sort the syscalls by number.
	sort.Slice(fullList, func(i, j int) bool {
		return fullList[i].Number < fullList[j].Number
	})

	if *jsonOut {
		j, err := json.Marshal(fullList)
		if err != nil {
			fmt.Printf("failed to marshal JSON: %v", err)
			os.Exit(1)
		}
		os.Stdout.Write(j)
		return
	}

	// Count syscalls and group by syscall number and support level
	supportMap := map[int]int{}
	for _, s := range fullList {
		supportLevel := s.SupportLevel()

		// If we already have set a higher level of support
		// keep the current value
		if current, ok := supportMap[s.Number]; ok && supportLevel < current {
			continue
		}

		supportMap[s.Number] = supportLevel
	}
	report := Report{
		Syscalls: fullList,
	}
	for _, s := range supportMap {
		switch s {
		case FULL_SUPPORT:
			report.Implemented += 1
		case PARTIAL_SUPPORT:
			report.Implemented += 1
		case UNIMPLEMENTED:
			report.Unimplemented += 1
		case UNKNOWN:
			report.Unknown += 1
		}
		report.Total += 1
	}

	err = mdTemplate.Execute(os.Stdout, report)
	if err != nil {
		fmt.Printf("failed to execute template: %v", err)
		os.Exit(1)
		return
	}
}
