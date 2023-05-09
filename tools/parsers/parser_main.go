// Copyright 2020 The gVisor Authors.
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

// Binary parser parses Benchmark data from golang benchmarks,
// puts it into a Schema for BigQuery, and sends it to BigQuery.
// parser will also initialize a table with the Benchmarks BigQuery schema.
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"gvisor.dev/gvisor/runsc/flag"
	bq "gvisor.dev/gvisor/tools/bigquery"
	"gvisor.dev/gvisor/tools/parsers"
)

const (
	initString       = "init"
	initDescription  = "initializes a new table with benchmarks schema"
	parseString      = "parse"
	parseDescription = "parses given benchmarks file and sends it to BigQuery table."
)

var (
	// The init command will create a new dataset/table in the given project and initialize
	// the table with the schema in //tools/bigquery/bigquery.go. If the table/dataset exists
	// or has been initialized, init has no effect and successfully returns.
	initCmd     = flag.NewFlagSet(initString, flag.ContinueOnError)
	initProject = initCmd.String("project", "", "GCP project to send benchmarks.")
	initDataset = initCmd.String("dataset", "", "dataset to send benchmarks data.")
	initTable   = initCmd.String("table", "", "table to send benchmarks data.")

	// The parse command parses benchmark data in `file` and sends it to the
	// requested table.
	parseCmd     = flag.NewFlagSet(parseString, flag.ContinueOnError)
	file         = parseCmd.String("file", "", "file to parse for benchmarks")
	name         = parseCmd.String("suite_name", "", "name of the benchmark suite")
	parseProject = parseCmd.String("project", "", "GCP project to send benchmarks.")
	parseDataset = parseCmd.String("dataset", "", "dataset to send benchmarks data.")
	parseTable   = parseCmd.String("table", "", "table to send benchmarks data.")
	official     = parseCmd.Bool("official", false, "mark input data as official.")
	runtime      = parseCmd.String("runtime", "", "runtime used to run the benchmark")
	debug        = parseCmd.Bool("debug", false, "print debug logs")
)

// initBenchmarks initializes a dataset/table in a BigQuery project.
func initBenchmarks(ctx context.Context) error {
	return bq.InitBigQuery(ctx, *initProject, *initDataset, *initTable, nil)
}

// parseBenchmarks parses the given file into the BigQuery schema,
// adds some custom data for the commit, and sends the data to BigQuery.
func parseBenchmarks(ctx context.Context) error {
	debugLog("Reading file: %s", *file)
	data, err := ioutil.ReadFile(*file)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", *file, err)
	}
	debugLog("Parsing output: %s", string(data))
	suite, err := parsers.ParseOutput(string(data), *name, *official)
	if err != nil {
		return fmt.Errorf("failed parse data: %v", err)
	}
	debugLog("Parsed benchmarks: %d", len(suite.Benchmarks))
	if len(suite.Benchmarks) < 1 {
		fmt.Fprintf(os.Stderr, "Failed to find benchmarks for file: %s", *file)
		return nil
	}

	extraConditions := []*bq.Condition{
		{
			Name:  "runtime",
			Value: *runtime,
		},
		{
			Name:  "version",
			Value: version,
		},
	}

	suite.Official = *official
	suite.Conditions = append(suite.Conditions, extraConditions...)
	debugLog("Sending benchmarks")
	return bq.SendBenchmarks(ctx, suite, *parseProject, *parseDataset, *parseTable, nil)
}

func main() {
	ctx := context.Background()
	switch {
	// the "init" command
	case len(os.Args) >= 2 && os.Args[1] == initString:
		if err := initCmd.Parse(os.Args[2:]); err != nil {
			log.Fatalf("Failed parse flags: %v\n", err)
			os.Exit(1)
		}
		if err := initBenchmarks(ctx); err != nil {
			failure := "failed to initialize project: %s dataset: %s table: %s: %v\n"
			log.Fatalf(failure, *parseProject, *parseDataset, *parseTable, err)
			os.Exit(1)
		}
	// the "parse" command.
	case len(os.Args) >= 2 && os.Args[1] == parseString:
		if err := parseCmd.Parse(os.Args[2:]); err != nil {
			log.Fatalf("Failed parse flags: %v\n", err)
			os.Exit(1)
		}
		if err := parseBenchmarks(ctx); err != nil {
			log.Fatalf("Failed parse benchmarks: %v\n", err)
			os.Exit(1)
		}
	default:
		printUsage()
		os.Exit(1)
	}
}

// printUsage prints the top level usage string.
func printUsage() {
	usage := `Usage: parser <command> <flags> ...

Available commands:
  %s     %s
  %s     %s
`
	log.Printf(usage, initCmd.Name(), initDescription, parseCmd.Name(), parseDescription)
}

func debugLog(msg string, args ...any) {
	if *debug {
		log.Printf(msg, args...)
	}
}
