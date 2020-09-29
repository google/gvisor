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

// Package util contains nogo-related utilities.
package util

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"strconv"
	"strings"
)

// findingRegexp is used to parse findings.
var findingRegexp = regexp.MustCompile(`([a-zA-Z0-9_\/\.-]+): (-|([a-zA-Z0-9_\/\.-]+):([0-9]+)(:([0-9]+))?): (.*)`)

const (
	categoryIndex        = 1
	fullPathAndLineIndex = 2
	fullPathIndex        = 3
	lineIndex            = 4
	messageIndex         = 7
)

// Finding is a single finding.
type Finding struct {
	Category string
	Path     string
	Line     int
	Message  string
}

// ExtractFindingsFromFile loads findings from a file.
func ExtractFindingsFromFile(filename string) ([]Finding, error) {
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return ExtractFindingsFromBytes(content)
}

// ExtractFindingsFromBytes loads findings from bytes.
func ExtractFindingsFromBytes(content []byte) (findings []Finding, err error) {
	lines := strings.Split(string(content), "\n")
	for _, singleLine := range lines {
		// Skip blank lines.
		singleLine = strings.TrimSpace(singleLine)
		if singleLine == "" {
			continue
		}
		m := findingRegexp.FindStringSubmatch(singleLine)
		if m == nil {
			// We shouldn't see findings like this.
			return findings, fmt.Errorf("poorly formated line: %v", singleLine)
		}
		if m[fullPathAndLineIndex] == "-" {
			continue // No source file available.
		}
		// Cleanup the message.
		message := m[messageIndex]
		message = strings.Replace(message, " → ", "\n → ", -1)
		message = strings.Replace(message, " or ", "\n or ", -1)
		// Construct a new annotation.
		lineNumber, _ := strconv.ParseUint(m[lineIndex], 10, 32)
		findings = append(findings, Finding{
			Category: m[categoryIndex],
			Path:     m[fullPathIndex],
			Line:     int(lineNumber),
			Message:  message,
		})
	}
	return findings, nil
}
