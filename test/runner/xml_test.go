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
	"slices"
	"testing"
)

func TestCollateXMLs(t *testing.T) {
	report := filepath.Join(t.TempDir(), "test.xml")
	inputs := []string{
		`<testsuites name="AllTests" tests="2" failures="0" disabled="0" errors="0" time="0.3" timestamp="2026-10-08T12:00:01">
  <properties><property name="first" value="one"/></properties>
  <testsuite name="First" tests="2" failures="0" skipped="0" time="0.3">
    <testcase name="A" classname="First" file="first.cc" line="10" time="0.1"/>
    <testcase name="B" classname="First" time="0.2"/>
  </testsuite>
</testsuites>`,
		`<testsuites name="AllTests" tests="3" failures="1" disabled="0" errors="0" time="0.6" timestamp="2026-10-08T12:00:00">
  <properties><property name="second" value="two"/></properties>
  <testsuite name="Second" tests="3" failures="1" skipped="1" time="0.6">
    <properties><property name="suite" value="kept"/></properties>
    <testcase name="Failure" classname="Second" time="0.3">
      <failure message="first &gt; second"><![CDATA[keep <testcase/> and > literally]]></failure>
      <failure message="another assertion">second failure</failure>
    </testcase>
    <testcase name="Skip" classname="Second" time="0.1"><skipped message="unavailable"/></testcase>
    <testcase name="Last" classname="Second" time="0.2"/>
  </testsuite>
</testsuites>`,
		`<testsuites name="AllTests" tests="0" failures="0" disabled="0" errors="0" time="0."/>`,
	}
	for i, input := range inputs {
		path := fmt.Sprintf("%s.%d%s", report, i, uniqueXMLSuffix)
		if err := os.WriteFile(path, []byte(input), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := collateXMLs(report); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	type property struct {
		Name  string `xml:"name,attr"`
		Value string `xml:"value,attr"`
	}
	var got struct {
		Name       string     `xml:"name,attr"`
		Tests      int        `xml:"tests,attr"`
		Failures   int        `xml:"failures,attr"`
		Errors     int        `xml:"errors,attr"`
		Disabled   int        `xml:"disabled,attr"`
		Time       string     `xml:"time,attr"`
		Timestamp  string     `xml:"timestamp,attr"`
		Properties []property `xml:"properties>property"`
		Suites     []struct {
			Name       string     `xml:"name,attr"`
			Tests      int        `xml:"tests,attr"`
			Failures   int        `xml:"failures,attr"`
			Skipped    int        `xml:"skipped,attr"`
			Time       string     `xml:"time,attr"`
			Properties []property `xml:"properties>property"`
			Cases      []struct {
				Name     string `xml:"name,attr"`
				Class    string `xml:"classname,attr"`
				File     string `xml:"file,attr"`
				Line     int    `xml:"line,attr"`
				Failures []struct {
					Message string `xml:"message,attr"`
					Text    string `xml:",chardata"`
				} `xml:"failure"`
				Skipped *struct {
					Message string `xml:"message,attr"`
				} `xml:"skipped"`
			} `xml:"testcase"`
		} `xml:"testsuite"`
	}
	if err := xml.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	var identities []string
	for _, suite := range got.Suites {
		for _, c := range suite.Cases {
			identities = append(identities, c.Class+"."+c.Name)
		}
	}
	want := []string{"First.A", "First.B", "Second.Failure", "Second.Skip", "Second.Last"}
	if !slices.Equal(identities, want) {
		t.Fatalf("case identities = %v, want %v", identities, want)
	}
	if got.Name != "AllTests" || got.Tests != 5 || got.Failures != 1 || got.Errors != 0 || got.Disabled != 0 || got.Time != "0.9" || got.Timestamp != "2026-10-08T12:00:00" {
		t.Fatalf("incorrect aggregate report: %+v", got)
	}
	if len(got.Suites) != 2 || len(got.Suites[0].Cases) != 2 || len(got.Suites[1].Cases) != 3 {
		t.Fatalf("missing suites or cases: %+v", got.Suites)
	}
	first, second := got.Suites[0], got.Suites[1]
	if first.Name != "First" || first.Tests != 2 || first.Failures != 0 || first.Time != "0.3" || second.Name != "Second" || second.Tests != 3 || second.Failures != 1 || second.Skipped != 1 || second.Time != "0.6" {
		t.Fatalf("suite metadata changed: %+v", got.Suites)
	}

	if first.Cases[0].File != "first.cc" || first.Cases[0].Line != 10 {
		t.Errorf("case location changed: %+v", first.Cases[0])
	}
	failures := second.Cases[0].Failures
	if len(failures) != 2 || failures[0].Message != "first > second" || failures[0].Text != "keep <testcase/> and > literally" || failures[1].Text != "second failure" {
		t.Errorf("failure contents changed: %+v", failures)
	}
	if skip := second.Cases[1].Skipped; skip == nil || skip.Message != "unavailable" {
		t.Errorf("skip contents changed: %+v", skip)
	}
	if !slices.Equal(got.Properties, []property{{"first", "one"}, {"second", "two"}}) || !slices.Equal(second.Properties, []property{{"suite", "kept"}}) {
		t.Errorf("properties changed: root=%+v suite=%+v", got.Properties, second.Properties)
	}
}

func TestCollateXMLsNoReports(t *testing.T) {
	report := filepath.Join(t.TempDir(), "test.xml")
	const original = `<testsuites><testsuite name="Original"><testcase name="Kept"/></testsuite></testsuites>`
	if err := os.WriteFile(report, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := collateXMLs(report); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatalf("original report changed without fragments: %q", data)
	}
}

func TestCollateXMLsMalformedReport(t *testing.T) {
	report := filepath.Join(t.TempDir(), "test.xml")
	const original = "previous report"
	if err := os.WriteFile(report, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(report+".bad"+uniqueXMLSuffix, []byte("<testsuites><testsuite>"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := collateXMLs(report); err == nil {
		t.Fatal("malformed input was accepted")
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != original {
		t.Fatalf("output replaced after parse failure: %q", data)
	}
}
