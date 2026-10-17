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

package main

import (
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// uniqueXMLSuffix is the suffix for individual per-testcase XML outputs.
const uniqueXMLSuffix = ".unique.xml"

// Keep each suite's complete contents and attributes, including failure and
// skipped elements, properties and any additional GoogleTest metadata.
type xmlTestSuite struct {
	Attributes []xml.Attr `xml:",any,attr"`
	Contents   string     `xml:",innerxml"`
}

type xmlProperties struct {
	Contents string `xml:",innerxml"`
}

type xmlTestSuites struct {
	XMLName    xml.Name       `xml:"testsuites"`
	Name       string         `xml:"name,attr"`
	Tests      int            `xml:"tests,attr"`
	Failures   int            `xml:"failures,attr"`
	Errors     int            `xml:"errors,attr"`
	Disabled   int            `xml:"disabled,attr"`
	Time       string         `xml:"time,attr"`
	Timestamp  string         `xml:"timestamp,attr,omitempty"`
	Properties *xmlProperties `xml:"properties,omitempty"`
	Suites     []xmlTestSuite `xml:"testsuite"`
}

func collateXMLs(origXML string) error {
	matches, err := filepath.Glob(origXML + ".*" + uniqueXMLSuffix)
	if err != nil {
		return fmt.Errorf("failed to glob individual XML files: %w", err)
	}
	if len(matches) == 0 {
		return nil
	}

	result := xmlTestSuites{Name: "AllTests"}
	var duration time.Duration
	for _, path := range matches {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("failed to read XML file %s: %w", path, err)
		}
		var report xmlTestSuites
		if err := xml.Unmarshal(data, &report); err != nil {
			return fmt.Errorf("failed to parse XML file %s: %w", path, err)
		}
		if report.Time != "" {
			elapsed, err := time.ParseDuration(report.Time + "s")
			if err != nil {
				return fmt.Errorf("invalid duration in XML file %s: %w", path, err)
			}
			duration += elapsed
		}
		result.Tests += report.Tests
		result.Failures += report.Failures
		result.Errors += report.Errors
		result.Disabled += report.Disabled
		if report.Properties != nil {
			if result.Properties == nil {
				result.Properties = &xmlProperties{}
			}
			result.Properties.Contents += report.Properties.Contents
		}
		// GoogleTest timestamps use a sortable ISO date/time representation.
		if report.Timestamp != "" && (result.Timestamp == "" || report.Timestamp < result.Timestamp) {
			result.Timestamp = report.Timestamp
		}
		result.Suites = append(result.Suites, report.Suites...)
	}
	result.Time = strconv.FormatFloat(duration.Seconds(), 'f', -1, 64)
	data, err := xml.Marshal(result)
	if err != nil {
		return fmt.Errorf("failed to encode collated XML: %w", err)
	}
	// Parse every input before replacing the output report.
	if err := os.WriteFile(origXML, append([]byte(xml.Header), data...), 0666); err != nil {
		return fmt.Errorf("failed to write collated XML file %s: %w", origXML, err)
	}
	return nil
}
