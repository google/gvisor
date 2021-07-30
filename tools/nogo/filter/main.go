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

// Binary filter is the filters and reports nogo findings.
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
	"gvisor.dev/gvisor/tools/worker"
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
	check       bool
)

func init() {
	flag.Var(&inputFiles, "input", "findings input files (gob format)")
	flag.StringVar(&outputFile, "output", "", "findings output file (json format)")
	flag.Var(&configFiles, "config", "findings configuration files")
	flag.BoolVar(&showConfig, "show-config", false, "dump configuration only")
	flag.BoolVar(&check, "check", false, "assume input is in json format")
}

func main() {
	worker.Work(run)
}

var (
	cachedFindings    = worker.NewCache("findings") // With nogo.FindingSet.
	cachedFiltered    = worker.NewCache("filtered") // With nogo.FindingSet.
	cachedConfigs     = worker.NewCache("configs")  // With nogo.Config.
	cachedFullConfigs = worker.NewCache("compiled") // With nogo.Config.
)

func loadFindings(filename string) nogo.FindingSet {
	return cachedFindings.Lookup([]string{filename}, func() worker.Sizer {
		r, err := os.Open(filename)
		if err != nil {
			log.Fatalf("unable to open input %q: %v", filename, err)
		}
		inputFindings, err := nogo.ExtractFindingsFrom(r, check /* json */)
		if err != nil {
			log.Fatalf("unable to extract findings from %s: %v", filename, err)
		}
		return inputFindings
	}).(nogo.FindingSet)
}

func loadConfig(filename string) *nogo.Config {
	return cachedConfigs.Lookup([]string{filename}, func() worker.Sizer {
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
		if showConfig {
			content, err := yaml.Marshal(&newConfig)
			if err != nil {
				log.Fatalf("error marshalling config: %v", err)
			}
			fmt.Fprintf(os.Stdout, "Loaded configuration from %s:\n%s\n", filename, string(content))
		}
		return &newConfig
	}).(*nogo.Config)
}

func loadConfigs(filenames []string) *nogo.Config {
	return cachedFullConfigs.Lookup(filenames, func() worker.Sizer {
		config := &nogo.Config{
			Global:    make(nogo.AnalyzerConfig),
			Analyzers: make(map[nogo.AnalyzerName]nogo.AnalyzerConfig),
		}
		for _, filename := range configFiles {
			config.Merge(loadConfig(filename))
			if showConfig {
				mergedBytes, err := yaml.Marshal(config)
				if err != nil {
					log.Fatalf("error marshalling config: %v", err)
				}
				fmt.Fprintf(os.Stdout, "Merged configuration:\n%s\n", string(mergedBytes))
			}
		}
		if err := config.Compile(); err != nil {
			log.Fatalf("error compiling config: %v", err)
		}
		return config
	}).(*nogo.Config)
}

func run([]string) int {
	// Open and merge all configuations.
	config := loadConfigs(configFiles)
	if showConfig {
		return 0
	}

	// Load and filer available findings.
	var filteredFindings []nogo.Finding
	for _, filename := range inputFiles {
		// Note that this applies a caching strategy to the filtered
		// findings, because *this is by far the most expensive part of
		// evaluation*. The set of findings is large and applying the
		// configuration is complex. Therefore, we segment this cache
		// on each individual raw findings input file and the
		// configuration files. Note that this cache is keyed on all
		// the configuration files and each individual raw findings, so
		// is guaranteed to be safe. This allows us to reuse the same
		// filter result many times over, because e.g. all standard
		// library findings will be available to all packages.
		filteredFindings = append(filteredFindings,
			cachedFiltered.Lookup(append(configFiles, filename), func() worker.Sizer {
				inputFindings := loadFindings(filename)
				filteredFindings := make(nogo.FindingSet, 0, len(inputFindings))
				for _, finding := range inputFindings {
					if ok := config.ShouldReport(finding); ok {
						filteredFindings = append(filteredFindings, finding)
					}
				}
				return filteredFindings
			}).(nogo.FindingSet)...)
	}

	// Write the output (if required).
	//
	// If the outputFile is specified, then we exit here. Otherwise,
	// we continue to write to stdout and treat like a test.
	//
	// Note that the output of the filter is always json, which is
	// human readable and the format that is consumed by tricorder.
	if outputFile != "" {
		w, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatalf("unable to open output file %q: %v", outputFile, err)
		}
		if err := nogo.WriteFindingsTo(w, filteredFindings, true /* json */); err != nil {
			log.Fatalf("unable to write findings: %v", err)
		}
		return 0
	}

	// Treat the run as a test.
	if len(filteredFindings) == 0 {
		fmt.Fprintf(os.Stdout, "PASS\n")
		return 0
	}
	for _, finding := range filteredFindings {
		fmt.Fprintf(os.Stdout, "%s\n", finding.String())
	}
	return 1
}
