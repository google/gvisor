// Copyright 2024 The gVisor Authors.
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

// profiletool deals with pprof profiles.
package main

import (
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/pprof/profile"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/flag"
)

var (
	mergeCmd   = flag.NewFlagSet("merge", flag.ContinueOnError)
	mergeOut   = mergeCmd.String("out", "/dev/stdout", "file to write the merged profile to")
	compactCmd = flag.NewFlagSet("compact", flag.ContinueOnError)
	compactOut = compactCmd.String("out", "/dev/stdout", "file to write the compacted profile to")

	allCommands = []*flag.FlagSet{mergeCmd, compactCmd}
	commandSet  = map[*flag.FlagSet]string{
		mergeCmd:   "merge two or more profile files into one",
		compactCmd: "minimize the size of a profile",
	}
)

// printUsage prints the top level usage string.
func printUsage() {
	usage := fmt.Sprintf(`Usage: %s <command> <flags> ...

Available commands:`, os.Args[0])
	fmt.Println(usage)
	for _, f := range allCommands {
		fmt.Printf("%s	%s\n", f.Name(), commandSet[f])
		f.PrintDefaults()
	}
}

// fail prints a warning message and exits.
func fail(msg string, values ...any) {
	log.Warningf(msg, values...)
	os.Exit(1)
}

// mergeProfiles merges two or more profile files into one.
func mergeProfiles() error {
	if err := mergeCmd.Parse(os.Args[2:]); err != nil {
		return fmt.Errorf("invalid flags: %w", err)
	}
	argPaths := mergeCmd.Args()
	var profilePaths []string
	for _, argPath := range argPaths {
		st, err := os.Stat(argPath)
		if err != nil {
			return fmt.Errorf("cannot stat %q: %w", argPath, err)
		}
		if st.IsDir() {
			filepath.Walk(argPath, func(path string, info os.FileInfo, err error) error {
				if err != nil {
					return fmt.Errorf("cannot walk %q: %w", path, err)
				}
				if info.IsDir() {
					return nil
				}
				profilePaths = append(profilePaths, path)
				return nil
			})
		} else {
			profilePaths = append(profilePaths, argPath)
		}
	}
	if len(profilePaths) == 0 {
		return errors.New("no profiles (or directories containing profiles) specified as positional arguments")
	}
	profiles := make([]*profile.Profile, len(profilePaths))
	for i, profilePath := range profilePaths {
		profileFile, err := os.Open(profilePath)
		if err != nil {
			return fmt.Errorf("cannot open %q: %w", profilePath, err)
		}
		prof, err := profile.Parse(profileFile)
		if err != nil {
			return fmt.Errorf("cannot parse %q as a profile: %w", profilePath, err)
		}
		profileFile.Close()
		profiles[i] = prof
	}
	merged, err := profile.Merge(profiles)
	if err != nil {
		return fmt.Errorf("cannot merge %q: %w", profilePaths, err)
	}
	merged = merged.Compact()
	mergedFile, err := os.Create(*mergeOut)
	if err != nil {
		return fmt.Errorf("cannot create %q: %w", *mergeOut, err)
	}
	defer mergedFile.Close()
	if err := writeMaxCompressionProfile(merged, mergedFile); err != nil {
		os.Remove(*mergeOut)
		return fmt.Errorf("cannot write merged profile to %q: %w", *mergeOut, err)
	}
	return nil
}

// compactProfile compacts a profile file.
func compactProfile() error {
	if err := compactCmd.Parse(os.Args[2:]); err != nil {
		return fmt.Errorf("invalid flags: %w", err)
	}
	if len(mergeCmd.Args()) != 1 {
		return errors.New("must provide exactly one profile name as positional argument")
	}
	profilePath := mergeCmd.Args()[0]
	profileFile, err := os.Open(profilePath)
	if err != nil {
		return fmt.Errorf("cannot open %q: %w", profilePath, err)
	}
	prof, err := profile.Parse(profileFile)
	if err != nil {
		return fmt.Errorf("cannot parse %q: %w", profilePath, err)
	}
	profileFile.Close()
	prof = prof.Compact()
	compactedFile, err := os.Create(*compactOut)
	if err != nil {
		return fmt.Errorf("cannot create %q: %w", *compactOut, err)
	}
	if err := writeMaxCompressionProfile(prof, compactedFile); err != nil {
		compactedFile.Close()
		os.Remove(*compactOut)
		return fmt.Errorf("cannot write compacted profile to %q: %w", *compactOut, err)
	}
	if err := compactedFile.Close(); err != nil {
		return fmt.Errorf("cannot close %q: %w", *compactOut, err)
	}
	return nil
}

// writeMaxCompressionProfile writes a profile to a file with the maximum
// compression level. The file handle is not closed.
func writeMaxCompressionProfile(p *profile.Profile, out *os.File) error {
	// The profile library writes profiles with the fastest (i.e. worst)
	// compression level by default, and does not allow setting the compression
	// level. So we compress it with the maximum level manually here.
	writer, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		return fmt.Errorf("cannot create zlib writer: %w", err)
	}
	if err := p.WriteUncompressed(writer); err != nil {
		return fmt.Errorf("cannot write profile to zlib writer: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("cannot close zlib writer: %w", err)
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case mergeCmd.Name():
		if err := mergeProfiles(); err != nil {
			fail(err.Error())
		}
	case compactCmd.Name():
		if err := compactProfile(); err != nil {
			fail(err.Error())
		}
	default:
		printUsage()
		os.Exit(1)
	}
}
