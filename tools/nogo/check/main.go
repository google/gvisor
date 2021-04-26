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
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"gvisor.dev/gvisor/tools/nogo"
	"gvisor.dev/gvisor/tools/worker"
)

var (
	packageFile    = flag.String("package", "", "package configuration file (in JSON format)")
	stdlibFile     = flag.String("stdlib", "", "stdlib configuration file (in JSON format)")
	findingsOutput = flag.String("findings", "", "output file (or stdout, if not specified)")
	factsOutput    = flag.String("facts", "", "output file for facts (optional)")
)

func loadConfig(file string, config interface{}) interface{} {
	// Load the configuration.
	f, err := os.Open(file)
	if err != nil {
		log.Fatalf("unable to open configuration %q: %v", file, err)
	}
	defer f.Close()
	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(config); err != nil {
		log.Fatalf("unable to decode configuration: %v", err)
	}
	return config
}

func main() {
	worker.Work(run)
}

func run([]string) int {
	var (
		findings []nogo.Finding
		factData []byte
		err      error
	)

	// Check & load the configuration.
	if *packageFile != "" && *stdlibFile != "" {
		log.Fatalf("unable to perform stdlib and package analysis; provide only one!")
	}

	// Run the configuration.
	if *stdlibFile != "" {
		// Perform stdlib analysis.
		c := loadConfig(*stdlibFile, new(nogo.StdlibConfig)).(*nogo.StdlibConfig)
		findings, factData, err = nogo.CheckStdlib(c, nogo.AllAnalyzers)
	} else if *packageFile != "" {
		// Perform standard analysis.
		c := loadConfig(*packageFile, new(nogo.PackageConfig)).(*nogo.PackageConfig)
		findings, factData, err = nogo.CheckPackage(c, nogo.AllAnalyzers, nil)
	} else {
		log.Fatalf("please provide at least one of package or stdlib!")
	}

	// Check that analysis was successful.
	if err != nil {
		log.Fatalf("error performing analysis: %v", err)
	}

	// Save facts.
	if *factsOutput != "" {
		if err := ioutil.WriteFile(*factsOutput, factData, 0644); err != nil {
			log.Fatalf("error saving findings to %q: %v", *factsOutput, err)
		}
	}

	// Write all findings.
	if *findingsOutput != "" {
		w, err := os.OpenFile(*findingsOutput, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			log.Fatalf("error opening output file %q: %v", *findingsOutput, err)
		}
		if err := nogo.WriteFindingsTo(w, findings, false /* json */); err != nil {
			log.Fatalf("error writing findings to %q: %v", *findingsOutput, err)
		}
	} else {
		for _, finding := range findings {
			fmt.Fprintf(os.Stdout, "%s\n", finding.String())
		}
	}

	return 0
}
