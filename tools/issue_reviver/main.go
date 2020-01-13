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

// Package main is the entry point for issue_reviver.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"gvisor.dev/gvisor/tools/issue_reviver/github"
	"gvisor.dev/gvisor/tools/issue_reviver/reviver"
)

var (
	owner     string
	repo      string
	tokenFile string
	path      string
	dryRun    bool
)

// Keep the options simple for now. Supports only a single path and repo.
func init() {
	flag.StringVar(&owner, "owner", "google", "Github project org/owner to look for issues")
	flag.StringVar(&repo, "repo", "gvisor", "Github repo to look for issues")
	flag.StringVar(&tokenFile, "oauth-token-file", "", "Path to file containing the OAUTH token to be used as credential to github")
	flag.StringVar(&path, "path", "", "Path to scan for TODOs")
	flag.BoolVar(&dryRun, "dry-run", false, "If set to true, no changes are made to issues")
}

func main() {
	flag.Parse()

	// Check for mandatory parameters.
	if len(owner) == 0 {
		fmt.Println("missing --owner option.")
		flag.Usage()
		os.Exit(1)
	}
	if len(repo) == 0 {
		fmt.Println("missing --repo option.")
		flag.Usage()
		os.Exit(1)
	}
	if len(path) == 0 {
		fmt.Println("missing --path option.")
		flag.Usage()
		os.Exit(1)
	}

	// Token is passed as a file so it doesn't show up in command line arguments.
	var token string
	if len(tokenFile) != 0 {
		bytes, err := ioutil.ReadFile(tokenFile)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		token = string(bytes)
	}

	bugger, err := github.NewBugger(token, owner, repo, dryRun)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error getting github issues:", err)
		os.Exit(1)
	}
	rev := reviver.New([]string{path}, []reviver.Bugger{bugger})
	if errs := rev.Run(); len(errs) > 0 {
		fmt.Fprintf(os.Stderr, "Encountered %d errors:\n", len(errs))
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "\t%v\n", err)
		}
		os.Exit(1)
	}
}
