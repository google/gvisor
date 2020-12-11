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

// Binary check is the nogo entrypoint.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	yaml "gopkg.in/yaml.v2"
	"gvisor.dev/gvisor/tools/nogo"
)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

var (
	inputFiles  stringList
	configFiles stringList
	outputFile  string
	showConfig  bool
)

func init() {
	flag.Var(&inputFiles, "input", "findings input files")
	flag.StringVar(&outputFile, "output", "", "findings output file")
	flag.Var(&configFiles, "config", "findings configuration files")
	flag.BoolVar(&showConfig, "show-config", false, "dump configuration only")
}

func main() {
	flag.Parse()

	// Load all available findings.
	var findings []nogo.Finding
	for _, filename := range inputFiles {
		inputFindings, err := nogo.ExtractFindingsFromFile(filename)
		if err != nil {
			log.Fatalf("unable to extract findings from %s: %v", filename, err)
		}
		findings = append(findings, inputFindings...)
	}

	// Open and merge all configuations.
	config := &nogo.Config{
		Global:    make(nogo.AnalyzerConfig),
		Analyzers: make(map[nogo.AnalyzerName]nogo.AnalyzerConfig),
	}
	for _, filename := range configFiles {
		content, err := ioutil.ReadFile(filename)
		if err != nil {
			log.Fatalf("unable to read %s: %v", filename, err)
		}
		var newConfig nogo.Config // For current file.
		dec := yaml.NewDecoder(bytes.NewBuffer(content))
		dec.SetStrict(true)
		if err := dec.Decode(&newConfig); err != nil {
			log.Fatalf("unable to decode %s: %v", filename, err)
		}
		config.Merge(&newConfig)
		if showConfig {
			content, err := yaml.Marshal(&newConfig)
			if err != nil {
				log.Fatalf("error marshalling config: %v", err)
			}
			mergedBytes, err := yaml.Marshal(config)
			if err != nil {
				log.Fatalf("error marshalling config: %v", err)
			}
			fmt.Fprintf(os.Stdout, "Loaded configuration from %s:\n%s\n", filename, string(content))
			fmt.Fprintf(os.Stdout, "Merged configuration:\n%s\n", string(mergedBytes))
		}
	}
	if err := config.Compile(); err != nil {
		log.Fatalf("error compiling config: %v", err)
	}
	if showConfig {
		os.Exit(0)
	}

	// Filter the findings (and aggregate by group).
	filteredFindings := make([]nogo.Finding, 0, len(findings))
	for _, finding := range findings {
		if ok := config.ShouldReport(finding); ok {
			filteredFindings = append(filteredFindings, finding)
		}
	}

	// Write the output (if required).
	//
	// If the outputFile is specified, then we exit here. Otherwise,
	// we continue to write to stdout and treat like a test.
	if outputFile != "" {
		if err := nogo.WriteFindingsToFile(filteredFindings, outputFile); err != nil {
			log.Fatalf("unable to write findings: %v", err)
		}
		return
	}

	// Treat the run as a test.
	if len(filteredFindings) == 0 {
		fmt.Fprintf(os.Stdout, "PASS\n")
		os.Exit(0)
	}
	for _, finding := range filteredFindings {
		fmt.Fprintf(os.Stdout, "%s\n", finding.String())
	}
	os.Exit(1)
}
