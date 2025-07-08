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
	"math"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/pprof/profile"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/flag"
)

var (
	mergeCmd              = flag.NewFlagSet("merge", flag.ContinueOnError)
	mergeOut              = mergeCmd.String("out", "/dev/stdout", "file to write the merged profile to")
	compactCmd            = flag.NewFlagSet("compact", flag.ContinueOnError)
	compactOut            = compactCmd.String("out", "/dev/stdout", "file to write the compacted profile to")
	runtimeInfoCmd        = flag.NewFlagSet("runtime-info", flag.ContinueOnError)
	checkSimilarCmd       = flag.NewFlagSet("check-similar", flag.ContinueOnError)
	checkSimilarQuiet     = checkSimilarCmd.Bool("quiet", false, "if set, do not print any output; comparison result is still provided as exit code")
	checkSimilarThreshold = checkSimilarCmd.Float64("threshold", 0.7, "threshold (between 0.0 and 1.0) above which the profiles are considered similar")

	allCommands = []*flag.FlagSet{mergeCmd, compactCmd, runtimeInfoCmd, checkSimilarCmd}
	commandSet  = map[*flag.FlagSet]string{
		mergeCmd:        "merge two or more profile files into one",
		compactCmd:      "minimize the size of a profile",
		runtimeInfoCmd:  "print a runtime information key that identifies dimensions impacting profiles (Go version, CPU architecture)",
		checkSimilarCmd: "check if two profiles are similar",
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
				if info.Size() == 0 {
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
		return errors.New("no non-empty profiles (or directories containing profiles) specified as positional arguments")
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

func runtimeInfo() error {
	goVersion := runtime.Version()
	if strings.Contains(goVersion, " ") {
		goVersion = strings.Split(goVersion, " ")[0]
	}
	fmt.Fprintf(os.Stdout, "%s-%s-%s", goVersion, runtime.GOOS, runtime.GOARCH)
	return nil
}

type comparisonKey struct {
	Filename              string
	FunctionName          string
	SystemName            string
	LineFromFunctionStart int64
	InlineTrace           string
}

func (k comparisonKey) isGoRuntime() bool {
	return strings.HasPrefix(k.FunctionName, "runtime.")
}

func (k comparisonKey) String() string {
	return fmt.Sprintf("%s:%s:%s:%d:%s", k.Filename, k.FunctionName, k.SystemName, k.LineFromFunctionStart, k.InlineTrace)
}

type aggregateProfileData struct {
	profile *profile.Profile
	keys    map[comparisonKey]float64
}

func aggregateProfile(p *profile.Profile) (aggregateProfileData, error) {
	keysCount := make(map[comparisonKey]int64)
	var lineKey strings.Builder
	addLine := func(line *profile.Line) {
		if lineKey.Len() > 0 {
			lineKey.WriteString(";")
		}
		if line.Function != nil {
			lineKey.WriteString(fmt.Sprintf("%s:%s:%d:%d", line.Function.Filename, line.Function.Name, line.Line-line.Function.StartLine, line.Column))
		} else {
			lineKey.WriteString(fmt.Sprintf("<unknown>:%d:%d", line.Line, line.Column))
		}
	}
	sampleValueIndex := -1
	for i, typ := range p.SampleType {
		if typ.Type == "cpu" {
			if sampleValueIndex != -1 {
				return aggregateProfileData{}, errors.New("multiple cpu columns found in profile")
			}
			sampleValueIndex = i
		}
	}
	if sampleValueIndex == -1 {
		return aggregateProfileData{}, errors.New("no cpu data found in profile")
	}
	var total int64
	for _, s := range p.Sample {
		value := s.Value[sampleValueIndex]
		stackHeight := len(s.Location)
		for i := stackHeight - 1; i >= 0; i-- {
			for _, loc := range s.Location[i : len(s.Location)-1] {
				if len(loc.Line) == 0 {
					continue
				}
				lastLine := loc.Line[len(loc.Line)-1]
				if lastLine.Function == nil {
					continue
				}
				key := comparisonKey{
					Filename:              lastLine.Function.Filename,
					FunctionName:          lastLine.Function.Name,
					SystemName:            lastLine.Function.SystemName,
					LineFromFunctionStart: lastLine.Line - lastLine.Function.StartLine,
				}
				if len(loc.Line) > 1 {
					lineKey.Reset()
					for _, line := range loc.Line[:len(loc.Line)-1] {
						addLine(&line)
					}
					key.InlineTrace = lineKey.String()
				}
				keysCount[key] += value
				total += value
			}
		}
	}
	result := aggregateProfileData{
		profile: p,
		keys:    make(map[comparisonKey]float64, len(keysCount)),
	}
	for key, count := range keysCount {
		result.keys[key] = float64(count) / float64(total)
	}
	return result, nil
}

// computeSimilarityScore computes the similarity score between two profiles.
// This score is between 0.0 (profiles are completely different) and 1.0
// (profiles are identical).
func computeSimilarityScore(a, b *profile.Profile) (float64, error) {
	aggA, err := aggregateProfile(a)
	if err != nil {
		return 0.0, fmt.Errorf("cannot aggregate profile A: %w", err)
	}
	aggB, err := aggregateProfile(b)
	if err != nil {
		return 0.0, fmt.Errorf("cannot aggregate profile B: %w", err)
	}
	if len(aggA.keys) == 0 || len(aggB.keys) == 0 {
		return 0.0, errors.New("one or both profiles are empty")
	}

	// The scoring algorithm is as follows:
	// Compute the union of all comparison keys for both profiles.
	// For each such key, look at the frequency in A and in B.
	// If a key is not found in a profile, its frequency is assumed to be
	// zero.
	// The error score for a key is the absolute difference between the
	// frequencies in A and B.
	// The total score is the sum of these differences across for all keys,
	// divided by the sum of the frequencies for all keys; effectively a
	// weighted-average of the non-overlap of samples weighted by their
	// frequency.
	// This is a number between 0.0 and 1.0, with 1.0 meaning completely
	// different profiles. We flip this score at the very end to convert it
	// from a measure of difference to a measure of similarity.
	var totalFreq float64
	var sum float64
	for key, freqA := range aggA.keys {
		if key.isGoRuntime() {
			continue
		}
		if freqB, inB := aggB.keys[key]; inB {
			log.Debugf("%v is in both profiles: %.2f%% vs %.2f%%", key, freqA*100.0, freqB*100.0)
			sum += math.Abs(freqA - freqB)
			totalFreq += max(freqA, freqB)
		} else {
			log.Debugf("%v is in A only: %.2f%%: %v", key, freqA*100.0)
			sum += freqA
			totalFreq += freqA
		}
	}
	for key, freqB := range aggB.keys {
		if key.isGoRuntime() {
			continue
		}
		if _, inA := aggA.keys[key]; !inA {
			log.Debugf("%v is in B only: %.2f%%: %v", key, freqB*100.0)
			sum += freqB
			totalFreq += freqB
		}
	}
	return 1.0 - sum/totalFreq, nil
}

func checkSimilarProfiles() error {
	if err := checkSimilarCmd.Parse(os.Args[2:]); err != nil {
		return fmt.Errorf("invalid flags: %w", err)
	}
	if len(checkSimilarCmd.Args()) != 2 {
		return errors.New("must provide exactly two profile names as positional arguments")
	}

	// Open both profiles.
	profileAPath := checkSimilarCmd.Args()[0]
	profileAFile, err := os.Open(profileAPath)
	if err != nil {
		return fmt.Errorf("cannot open %q: %w", profileAPath, err)
	}
	defer profileAFile.Close()
	profileA, err := profile.Parse(profileAFile)
	if err != nil {
		return fmt.Errorf("cannot parse %q: %w", profileAPath, err)
	}
	profileA = profileA.Compact()
	profileBPath := checkSimilarCmd.Args()[1]
	profileBFile, err := os.Open(profileBPath)
	if err != nil {
		return fmt.Errorf("cannot open %q: %w", profileBPath, err)
	}
	defer profileBFile.Close()
	profileB, err := profile.Parse(profileBFile)
	if err != nil {
		return fmt.Errorf("cannot parse %q: %w", profileBPath, err)
	}
	profileB = profileB.Compact()

	// Check similarity.
	similarScore, err := computeSimilarityScore(profileA, profileB)
	if err != nil {
		return fmt.Errorf("cannot compute similarity score: %w", err)
	}
	if !*checkSimilarQuiet {
		if similarScore < *checkSimilarThreshold {
			fmt.Fprintf(os.Stderr, "The profiles are %.2f%% similar, which is under the threshold of %.2f%%.\n", 100.0*similarScore, 100.0**checkSimilarThreshold)
		} else {
			fmt.Fprintf(os.Stderr, "The profiles are %.2f%% similar, which is above the threshold of %.2f%%.\n", 100.0*similarScore, 100.0**checkSimilarThreshold)
		}
	}
	if similarScore < *checkSimilarThreshold {
		os.Exit(1)
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case runtimeInfoCmd.Name():
		if err := runtimeInfo(); err != nil {
			fail(err.Error())
		}
	case mergeCmd.Name():
		if err := mergeProfiles(); err != nil {
			fail(err.Error())
		}
	case compactCmd.Name():
		if err := compactProfile(); err != nil {
			fail(err.Error())
		}
	case checkSimilarCmd.Name():
		if err := checkSimilarProfiles(); err != nil {
			fail(err.Error())
		}
	default:
		printUsage()
		os.Exit(1)
	}
}
