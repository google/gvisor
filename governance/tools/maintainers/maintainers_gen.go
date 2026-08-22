// Copyright 2026 The gVisor Authors.
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

// Command maintainers_gen generates the contents of .github/reviewer.json and
// MAINTAINERS.md from the maintainer roster in governance/maintainers.yaml.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"
)

var (
	input  = flag.String("input", "", "path to maintainers.yaml")
	format = flag.String("format", "reviewer.json", `output format: "reviewer.json" or "MAINTAINERS.md"`)
	output = flag.String("output", "", "path to write to; defaults to stdout")
)

// pastAffiliation is a past employer of a maintainer.
type pastAffiliation struct {
	Affiliation string `yaml:"affiliation"`
	Until       string `yaml:"until"`
}

// maintainer is a single entry of the maintainer roster.
type maintainer struct {
	Name             string            `yaml:"name"`
	GitHub           string            `yaml:"github"`
	Affiliation      string            `yaml:"affiliation"`
	PastAffiliations []pastAffiliation `yaml:"past_affiliation"`
	Started          string            `yaml:"started"`
	Status           string            `yaml:"status"`
}

// roster is the schema of maintainers.yaml.
type roster struct {
	Maintainers []maintainer `yaml:"maintainers"`
}

// parseStatus splits a status into its kind ("ACTIVE", "HIATUS_SINCE" or
// "EMERITUS_SINCE") and date, and validates both.
func parseStatus(status string) (string, string, error) {
	kind, date, hasDate := strings.Cut(status, ":")
	if hasDate {
		if _, err := time.Parse("2006-01-02", date); err != nil {
			return "", "", fmt.Errorf("invalid date in status %q", status)
		}
	}
	switch {
	case kind == "ACTIVE" && !hasDate:
	case kind == "HIATUS_SINCE" && hasDate:
	case kind == "EMERITUS_SINCE" && hasDate:
	default:
		return "", "", fmt.Errorf("invalid status %q", status)
	}
	return kind, date, nil
}

// parseRoster parses and validates maintainers.yaml contents.
func parseRoster(yamlData []byte) (*roster, error) {
	dec := yaml.NewDecoder(bytes.NewReader(yamlData))
	dec.KnownFields(true)
	var r roster
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("cannot parse roster: %w", err)
	}
	seen := make(map[string]bool, len(r.Maintainers))
	var prev maintainer
	for _, m := range r.Maintainers {
		if m.Name == "" || m.GitHub == "" || m.Affiliation == "" || m.Started == "" || m.Status == "" {
			return nil, fmt.Errorf("maintainer %+v: name, github, affiliation, started and status are required", m)
		}
		if _, err := time.Parse("2006-01-02", m.Started); err != nil {
			return nil, fmt.Errorf("maintainer %q: invalid started date %q", m.GitHub, m.Started)
		}
		for _, p := range m.PastAffiliations {
			if p.Affiliation == "" {
				return nil, fmt.Errorf("maintainer %q: past_affiliation entries require an affiliation", m.GitHub)
			}
			if _, err := time.Parse("2006-01-02", p.Until); err != nil {
				return nil, fmt.Errorf("maintainer %q: invalid until date %q in past_affiliation", m.GitHub, p.Until)
			}
		}
		if _, _, err := parseStatus(m.Status); err != nil {
			return nil, fmt.Errorf("maintainer %q: %w", m.GitHub, err)
		}
		if m.Started < prev.Started {
			return nil, fmt.Errorf("maintainers are not sorted by started date: %q (%s) comes after %q (%s)", m.Name, m.Started, prev.Name, prev.Started)
		}
		prev = m
		if seen[m.GitHub] {
			return nil, fmt.Errorf("duplicate maintainer %q", m.GitHub)
		}
		seen[m.GitHub] = true
	}
	return &r, nil
}

// generateReviewerJSON renders `reviewer.json` contents.
func generateReviewerJSON(r *roster) ([]byte, error) {
	reviewers := make(map[string]bool, len(r.Maintainers))
	for _, m := range r.Maintainers {
		kind, _, _ := parseStatus(m.Status)
		if kind == "EMERITUS_SINCE" {
			continue
		}
		reviewers[m.GitHub] = kind == "ACTIVE"
	}
	jsonData, err := json.MarshalIndent(reviewers, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("cannot marshal reviewers: %w", err)
	}
	return append(jsonData, '\n'), nil
}

// formatTable renders a markdown table with columns formatted.
func formatTable(headers []string, rows [][]string) string {
	numCols := len(headers)
	colWidths := make([]int, numCols)
	for i, h := range headers {
		colWidths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}
	var b strings.Builder
	// Header
	for i, h := range headers {
		if i > 0 {
			b.WriteString(" | ")
		}
		if i == numCols-1 {
			b.WriteString(h)
		} else {
			b.WriteString(h)
			b.WriteString(strings.Repeat(" ", colWidths[i]-len(h)))
		}
	}
	b.WriteString("\n")
	// Separator
	for i := 0; i < numCols; i++ {
		if i > 0 {
			b.WriteString(" | ")
		}
		b.WriteString(strings.Repeat("-", colWidths[i]))
	}
	b.WriteString("\n")
	// Rows
	for _, row := range rows {
		for i, cell := range row {
			if i > 0 {
				b.WriteString(" | ")
			}
			if i == numCols-1 {
				b.WriteString(cell)
			} else {
				b.WriteString(cell)
				b.WriteString(strings.Repeat(" ", colWidths[i]-len(cell)))
			}
		}
		b.WriteString("\n")
	}
	return b.String()
}

// generateMaintainersMD renders `MAINTAINERS.md` contents.
func generateMaintainersMD(r *roster) ([]byte, error) {
	var b bytes.Buffer
	b.WriteString("<!-- Generated from governance/maintainers.yaml by\n")
	b.WriteString("     //governance/tools/maintainers:maintainers_gen; do not edit directly. -->\n\n")
	b.WriteString("The current maintainers of the gVisor project are listed below.\n\n")

	var activeRows [][]string
	for _, m := range r.Maintainers {
		if kind, _, _ := parseStatus(m.Status); kind != "EMERITUS_SINCE" {
			activeRows = append(activeRows, []string{
				m.Name,
				fmt.Sprintf("[@%s](https://github.com/%s)", m.GitHub, m.GitHub),
				m.Affiliation,
			})
		}
	}
	b.WriteString(formatTable([]string{"Name", "GitHub ID", "Company/Organization"}, activeRows))

	b.WriteString(`
## Emeritus Maintainers

Maintainers who have stepped back from active participation are recognized here.
Emeritus maintainers do not have voting rights or merge access but are
recognized for their contributions and may be consulted on project matters.

A maintainer is moved to emeritus status after 12 months of inactivity, or by
request. An emeritus maintainer may return to active status through the normal
maintainer nomination process.

`)

	var emeritusRows [][]string
	for _, m := range r.Maintainers {
		if kind, date, _ := parseStatus(m.Status); kind == "EMERITUS_SINCE" {
			emeritusRows = append(emeritusRows, []string{
				m.Name,
				fmt.Sprintf("[@%s](https://github.com/%s)", m.GitHub, m.GitHub),
				date,
			})
		}
	}
	b.WriteString(formatTable([]string{"Name", "GitHub ID", "Date moved to emeritus"}, emeritusRows))

	return b.Bytes(), nil
}

func main() {
	flag.Parse()
	if *input == "" {
		fmt.Fprintln(os.Stderr, "must specify -input")
		os.Exit(1)
	}
	yamlData, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot read roster: %v\n", err)
		os.Exit(1)
	}
	r, err := parseRoster(yamlData)
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot parse %s: %v\n", *input, err)
		os.Exit(1)
	}
	var outData []byte
	switch *format {
	case "reviewer.json":
		outData, err = generateReviewerJSON(r)
	case "MAINTAINERS.md":
		outData, err = generateMaintainersMD(r)
	default:
		err = fmt.Errorf("invalid format %q", *format)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "cannot generate output: %v\n", err)
		os.Exit(1)
	}
	if *output == "" {
		os.Stdout.Write(outData)
	} else if err := os.WriteFile(*output, outData, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "cannot write %s: %v\n", *output, err)
		os.Exit(1)
	}
}
