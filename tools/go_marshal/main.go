// Copyright 2019 Google LLC
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

// go_marshal is a code generation utility for automatically generating code to
// marshal go data structures to memory.
//
// This binary is typically run as part of the build process, and is invoked by
// the go_marshal bazel rule defined in defs.bzl.
//
// See README.md.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"gvisor.dev/gvisor/tools/go_marshal/gomarshal"
)

var (
	pkg            = flag.String("pkg", "", "output package")
	output         = flag.String("output", "", "output file")
	outputTest     = flag.String("output_test", "", "output file for tests")
	imports        = flag.String("imports", "", "comma-separated list of extra packages to import in generated code")
	declarationPkg = flag.String("declarationPkg", "", "import path of target declaring the types we're generating on")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s <input go src files>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}

	if *pkg == "" {
		flag.Usage()
		fmt.Fprint(os.Stderr, "Flag -pkg must be provided.\n")
		os.Exit(1)
	}

	var extraImports []string
	if len(*imports) > 0 {
		// Note: strings.Split(s, sep) returns s if sep doesn't exist in s. Thus
		// we check for an empty imports list to avoid emitting an empty string
		// as an import.
		extraImports = strings.Split(*imports, ",")
	}
	g, err := gomarshal.NewGenerator(flag.Args(), *output, *outputTest, *pkg, *declarationPkg, extraImports)
	if err != nil {
		panic(err)
	}

	if err := g.Run(); err != nil {
		panic(err)
	}
}
