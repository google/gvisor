// Copyright 2019 The gVisor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Binary syscalldocs generates system call markdown.
package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
)

// CompatibilityInfo is the collection of all information.
type CompatibilityInfo map[string]map[string]ArchInfo

// ArchInfo is compatbility doc for an architecture.
type ArchInfo struct {
	// Syscalls maps syscall number for the architecture to the doc.
	Syscalls map[uintptr]SyscallDoc `json:"syscalls"`
}

// SyscallDoc represents a single item of syscall documentation.
type SyscallDoc struct {
	Name    string   `json:"name"`
	Support string   `json:"support"`
	Note    string   `json:"note,omitempty"`
	URLs    []string `json:"urls,omitempty"`
}

var mdTemplate = template.Must(template.New("out").Parse(`---
title: {{.Title}}
description: Syscall Compatibility Reference Documentation for {{.OS}}/{{.Arch}}
layout: docs
category: Compatibility
weight: 50
permalink: /docs/user_guide/compatibility/{{.OS}}/{{.Arch}}/
include_in_menu: True
---

This table is a reference of {{.OS}} syscalls for the {{.Arch}} architecture and
their compatibility status in gVisor. gVisor does not support all syscalls and
some syscalls may have a partial implementation.

This page is automatically generated from the source code.

Of {{.Total}} syscalls, {{.Supported}} syscalls have a full or partial
implementation. There are currently {{.Unsupported}} unsupported
syscalls. {{if .Undocumented}}{{.Undocumented}} syscalls are not yet documented.{{end}}

<table>
  <thead>
    <tr>
      <th>#</th>
      <th>Name</th>
      <th>Support</th>
      <th>Notes</th>
    </tr>
  </thead>
  <tbody>
 	{{range $i, $syscall := .Syscalls}}
    <tr id="{{.Name}}">
      <td><a href="#{{.Name}}">{{.Number}}</a></td>
      <td><a href="{{.DocURL}}" target="_blank" rel="noopener">{{.Name}}</a></td>
      <td>{{.Support}}</td>
	  <td>{{.Note}} {{range $i, $url := .URLs}}<br/>See: <a href="{{.}}">{{.}}</a>{{end}}</td>
    </tr>
	{{end}}
  </tbody>
</table>
`))

// Fatalf writes a message to stderr and exits with error code 1
func Fatalf(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, format, a...)
	os.Exit(1)
}

// syscallDocURL returns a doc url for a given syscall, doing its best to return a url that exists.
func syscallDocURL(name string) string {
	customDocs := map[string]string{
		"io_pgetevents":     "https://man7.org/linux/man-pages/man2/syscalls.2.html",
		"rseq":              "https://man7.org/linux/man-pages/man2/syscalls.2.html",
		"io_uring_setup":    "https://manpages.debian.org/buster-backports/liburing-dev/io_uring_setup.2.en.html",
		"io_uring_enter":    "https://manpages.debian.org/buster-backports/liburing-dev/io_uring_enter.2.en.html",
		"io_uring_register": "https://manpages.debian.org/buster-backports/liburing-dev/io_uring_register.2.en.html",
		"open_tree":         "https://man7.org/linux/man-pages/man2/syscalls.2.html",
		"move_mount":        "https://man7.org/linux/man-pages/man2/syscalls.2.html",
		"fsopen":            "https://man7.org/linux/man-pages/man2/syscalls.2.html",
		"fsconfig":          "https://man7.org/linux/man-pages/man2/syscalls.2.html",
		"fsmount":           "https://man7.org/linux/man-pages/man2/syscalls.2.html",
		"fspick":            "https://man7.org/linux/man-pages/man2/syscalls.2.html",
	}
	if url, ok := customDocs[name]; ok {
		return url
	}
	return fmt.Sprintf("http://man7.org/linux/man-pages/man2/%s.2.html", name)
}

func main() {
	inputFlag := flag.String("in", "-", "File to input ('-' for stdin)")
	outputDir := flag.String("out", ".", "Directory to output files.")

	flag.Parse()

	var input io.Reader
	if *inputFlag == "-" {
		input = os.Stdin
	} else {
		i, err := os.Open(*inputFlag)
		if err != nil {
			Fatalf("Error opening %q: %v", *inputFlag, err)
		}
		input = i
	}
	input = bufio.NewReader(input)

	var info CompatibilityInfo
	d := json.NewDecoder(input)
	if err := d.Decode(&info); err != nil {
		Fatalf("Error reading json: %v", err)
	}

	weight := 0
	for osName, osInfo := range info {
		for archName, archInfo := range osInfo {
			outDir := filepath.Join(*outputDir, osName)
			outFile := filepath.Join(outDir, archName+".md")

			if err := os.MkdirAll(outDir, 0755); err != nil {
				Fatalf("Error creating directory %q: %v", *outputDir, err)
			}

			f, err := os.OpenFile(outFile, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0644)
			if err != nil {
				Fatalf("Error opening file %q: %v", outFile, err)
			}
			defer f.Close()

			weight += 10
			data := struct {
				Title        string
				OS           string
				Arch         string
				Weight       int
				Total        int
				Supported    int
				Unsupported  int
				Undocumented int
				Syscalls     []struct {
					Name    string
					Number  uintptr
					DocURL  string
					Support string
					Note    string
					URLs    []string
				}
			}{
				Title:        strings.Title(osName) + "/" + archName,
				OS:           osName,
				Arch:         archName,
				Weight:       weight,
				Total:        0,
				Supported:    0,
				Unsupported:  0,
				Undocumented: 0,
				Syscalls: []struct {
					Name    string
					Number  uintptr
					DocURL  string
					Support string
					Note    string
					URLs    []string
				}{},
			}

			for num, s := range archInfo.Syscalls {
				switch s.Support {
				case "Full Support", "Partial Support":
					data.Supported++
				case "Unimplemented":
					data.Unsupported++
				default:
					data.Undocumented++
				}
				data.Total++

				for i := range s.URLs {
					if !strings.HasPrefix(s.URLs[i], "http://") && !strings.HasPrefix(s.URLs[i], "https://") {
						s.URLs[i] = "https://" + s.URLs[i]
					}
				}

				data.Syscalls = append(data.Syscalls, struct {
					Name    string
					Number  uintptr
					DocURL  string
					Support string
					Note    string
					URLs    []string
				}{
					Name:    s.Name,
					Number:  num,
					DocURL:  syscallDocURL(s.Name),
					Support: s.Support,
					Note:    s.Note,
					URLs:    s.URLs,
				})
			}

			sort.Slice(data.Syscalls, func(i, j int) bool {
				return data.Syscalls[i].Number < data.Syscalls[j].Number
			})

			if err := mdTemplate.Execute(f, data); err != nil {
				Fatalf("Error writing file %q: %v", outFile, err)
			}
		}
	}
}
