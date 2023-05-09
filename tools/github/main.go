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

// Binary github is the entry point for GitHub utilities.
package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/google/go-github/github"
	"golang.org/x/oauth2"
	"gvisor.dev/gvisor/tools/github/reviver"
)

var (
	owner     string
	repo      string
	tokenFile string
	paths     stringList
	commit    string
	dryRun    bool
)

type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(value string) error {
	*s = append(*s, value)
	return nil
}

// Keep the options simple for now. Supports only a single path and repo.
func init() {
	flag.StringVar(&owner, "owner", "", "GitHub project org/owner")
	flag.StringVar(&repo, "repo", "", "GitHub repo")
	flag.StringVar(&tokenFile, "oauth-token-file", "", "file containing the GitHub token (or GITHUB_TOKEN is set)")
	flag.Var(&paths, "path", "path(s) to scan (required for revive)")
	flag.BoolVar(&dryRun, "dry-run", false, "just print changes to be made")
}

func filterPaths(paths []string) (existing []string) {
	for _, path := range paths {
		if _, err := os.Stat(path); err != nil {
			log.Printf("WARNING: skipping %v: %v", path, err)
			continue
		}
		existing = append(existing, path)
	}
	return
}

func main() {
	// Set defaults from the environment.
	repository := os.Getenv("GITHUB_REPOSITORY")
	if parts := strings.SplitN(repository, "/", 2); len(parts) == 2 {
		owner = parts[0]
		repo = parts[1]
	}

	// Parse flags.
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "usage: %s [options] <command>\n", os.Args[0])
		fmt.Fprintf(flag.CommandLine.Output(), "commands: revive, nogo\n")
		flag.PrintDefaults()
	}
	flag.Parse()
	args := flag.Args()
	if len(args) != 1 {
		fmt.Fprintf(flag.CommandLine.Output(), "extra arguments: %s\n", strings.Join(args[1:], ", "))
		flag.Usage()
		os.Exit(1)
	}

	// Check for mandatory parameters.
	command := args[0]
	if len(owner) == 0 {
		fmt.Fprintln(flag.CommandLine.Output(), "missing --owner option.")
		flag.Usage()
		os.Exit(1)
	}
	if len(repo) == 0 {
		fmt.Fprintln(flag.CommandLine.Output(), "missing --repo option.")
		flag.Usage()
		os.Exit(1)
	}
	filteredPaths := filterPaths(paths)
	if len(filteredPaths) == 0 {
		fmt.Fprintln(flag.CommandLine.Output(), "no valid --path options provided.")
		flag.Usage()
		os.Exit(1)
	}

	// The access token may be passed as a file so it doesn't show up in
	// command line arguments. It also may be provided through the
	// environment to faciliate use through GitHub's CI system.
	token := os.Getenv("GITHUB_TOKEN")
	if len(tokenFile) != 0 {
		bytes, err := ioutil.ReadFile(tokenFile)
		if err != nil {
			fmt.Println(err.Error())
			os.Exit(1)
		}
		token = string(bytes)
	}
	var client *github.Client
	if len(token) == 0 {
		// Client is unauthenticated.
		client = github.NewClient(nil)
	} else {
		// Using the above token.
		ts := oauth2.StaticTokenSource(
			&oauth2.Token{AccessToken: token},
		)
		tc := oauth2.NewClient(context.Background(), ts)
		client = github.NewClient(tc)
	}

	switch command {
	case "revive":
		// Load existing GitHub bugs.
		bugger, err := reviver.NewGitHubBugger(client, owner, repo, dryRun)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error getting github issues: %v\n", err)
			os.Exit(1)
		}
		// Scan the provided path.
		rev := reviver.New(filteredPaths, []reviver.Bugger{bugger})
		if errs := rev.Run(); len(errs) > 0 {
			fmt.Fprintf(os.Stderr, "Encountered %d errors:\n", len(errs))
			for _, err := range errs {
				fmt.Fprintf(os.Stderr, "\t%v\n", err)
			}
			os.Exit(1)
		}
	default:
		// Not a known command.
		fmt.Fprintf(flag.CommandLine.Output(), "unknown command: %s\n", command)
		flag.Usage()
		os.Exit(1)
	}
}
