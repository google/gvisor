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

// Package main sets up and runs the NVIDIA driver differ.
package main

import (
	"flag"
	"fmt"
	"os"

	"gvisor.dev/gvisor/tools/nvidia_driver_differ/parser"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"

	_ "embed" // Necessary to use go:embed.
)

var (
	baseVersionString = flag.String("base", "", "The first version to compare. This is the version that will be used as the base for the diff.")
	nextVersionString = flag.String("next", "", "The second version to compare.")
)

//go:embed driver_ast_parser
var driverParserBinary []byte

// createParserBinary creates a temporary file containing the driver_ast_parser
// binary, and returns the path to it.
func createParserBinary() (string, error) {
	tmpFile, err := os.CreateTemp(os.TempDir(), "driver_ast_parser_*")
	if err != nil {
		return "", fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer func() {
		if err := tmpFile.Close(); err != nil {
			log.Warningf("failed to close driver_ast_parser binary: %w", err)
		}
	}()

	if _, err := tmpFile.Write(driverParserBinary); err != nil {
		return "", fmt.Errorf("failed to write to temporary file: %w", err)
	}

	if err := tmpFile.Chmod(0500); err != nil {
		return "", fmt.Errorf("failed to make file executable: %w", err)
	}

	return tmpFile.Name(), nil
}

// Main is the main function for the NVIDIA driver differ.
func Main() error {
	// Read driver version from command line
	baseVersion, err := nvconf.DriverVersionFrom(*baseVersionString)
	if err != nil {
		return fmt.Errorf("failed to parse driver version %s: %w", *baseVersionString, err)
	}
	nextVersion, err := nvconf.DriverVersionFrom(*nextVersionString)
	if err != nil {
		return fmt.Errorf("failed to parse driver version %s: %w", *nextVersionString, err)
	}

	// Unpack embedded driver_ast_parser
	parserFile, err := createParserBinary()
	if err != nil {
		return fmt.Errorf("failed to unpack driver_ast_parser binary: %w", err)
	}
	defer func() {
		if err := os.Remove(parserFile); err != nil {
			log.Warningf("failed to close driver_ast_parser binary: %w", err)
		}
	}()

	// Parse through nvproxy to find the list of structs used
	nvproxy.Init()
	nvproxyInfo, ok := nvproxy.SupportedIoctls(baseVersion)
	if !ok {
		return fmt.Errorf("failed to get struct names for version %v", baseVersion)
	}

	// Create runner for driver_ast_parser
	runner, err := parser.NewRunner(parserFile)
	if err != nil {
		return fmt.Errorf("failed to create runner for driver_ast_parser: %w", err)
	}
	defer func() {
		if err := runner.Cleanup(); err != nil {
			log.Warningf("failed to clean up runner: %w", err)
		}
	}()

	// Write list of structs to file
	if err := runner.CreateInputFile(nvproxyInfo); err != nil {
		return fmt.Errorf("failed to create temporary structs list: %w", err)
	}

	// Run driver_ast_parser on .cc files for both versions
	log.Infof("Parsing driver version %s", baseVersion)
	baseDefs, err := runner.ParseDriver(baseVersion)
	if err != nil {
		return fmt.Errorf("failed to run driver_ast_parser on base version: %w", err)
	}
	log.Infof("Parsing driver version %s", nextVersion)
	nextDefs, err := runner.ParseDriver(nextVersion)
	if err != nil {
		return fmt.Errorf("failed to run driver_ast_parser on next version: %w", err)
	}

	// Create set of all records found in both versions. This will be a superset of the list of
	// structs generated above, since the Clang tool also reports recursive and anonymous structs.
	log.Infof("Comparing record definitions between %s and %s", baseVersion, nextVersion)
	recordsFound := make(map[nvproxy.DriverStructName]struct{})
	for name := range baseDefs.Records {
		recordsFound[name] = struct{}{}
	}
	for name := range nextDefs.Records {
		recordsFound[name] = struct{}{}
	}

	for name := range recordsFound {
		// Check that the struct exists in both files.
		baseRecordDef, baseOk := baseDefs.Records[name]
		if !baseOk {
			log.Infof("type %s not found in first source file", name)
		}
		nextRecordDef, nextOk := nextDefs.Records[name]
		if !nextOk {
			log.Infof("type %s not found in second source file", name)
		}
		if !baseOk || !nextOk {
			continue
		}

		if !baseRecordDef.Equals(nextRecordDef) {
			log.Infof("\n%v", parser.GetRecordDiff(name, baseRecordDef, nextRecordDef))
		}
	}

	log.Infof("Comparing type aliases between %s and %s", baseVersion, nextVersion)
	aliasesFound := make(map[nvproxy.DriverStructName]struct{})
	for name := range baseDefs.Aliases {
		aliasesFound[name] = struct{}{}
	}
	for name := range nextDefs.Aliases {
		aliasesFound[name] = struct{}{}
	}

	for name := range aliasesFound {
		baseAlias, baseOk := baseDefs.Aliases[name]
		if !baseOk {
			log.Infof("alias %s not found in first source file", name)
		}
		nextAlias, nextOk := nextDefs.Aliases[name]
		if !nextOk {
			log.Infof("alias %s not found in second source file", name)
		}
		if !baseOk || !nextOk {
			continue
		}

		if baseAlias.Type != nextAlias.Type {
			log.Infof("alias %s changed from %s to %s", name, baseAlias.Type, nextAlias.Type)
		}
	}

	log.Infof("Comparing constants between %s and %s", baseVersion, nextVersion)
	constantsFound := make(map[nvproxy.IoctlName]struct{})
	for name := range baseDefs.Constants {
		constantsFound[name] = struct{}{}
	}
	for name := range nextDefs.Constants {
		constantsFound[name] = struct{}{}
	}
	for name := range constantsFound {
		baseConstant, baseOk := baseDefs.Constants[name]
		if !baseOk {
			log.Infof("constant %s not found in first source file", name)
		}
		nextConstant, nextOk := nextDefs.Constants[name]
		if !nextOk {
			log.Infof("constant %s not found in second source file", name)
		}
		if !baseOk || !nextOk {
			continue
		}
		if baseConstant != nextConstant {
			log.Infof("constant %s changed from %d to %d", name, baseConstant, nextConstant)
		}
	}

	// Check if any constants or structs from the input list were missing.
	var missingStructs []nvproxy.DriverStructName
	var missingConstants []nvproxy.IoctlName
	checkMissing := func(ioctl nvproxy.IoctlInfo) {
		if ioctl.Name == "" {
			return
		}
		for _, structDef := range ioctl.Structs {
			_, isRecord := recordsFound[structDef.Name]
			_, isAlias := aliasesFound[structDef.Name]
			if !isRecord && !isAlias {
				missingStructs = append(missingStructs, structDef.Name)
			}
		}
		if _, ok := constantsFound[ioctl.Name]; !ok {
			missingConstants = append(missingConstants, ioctl.Name)
		}
	}
	for _, ioctl := range nvproxyInfo.FrontendInfos {
		checkMissing(ioctl)
	}
	for _, ioctl := range nvproxyInfo.ControlInfos {
		checkMissing(ioctl)
	}
	for _, ioctl := range nvproxyInfo.AllocationInfos {
		checkMissing(ioctl)
	}
	for _, ioctl := range nvproxyInfo.UvmInfos {
		checkMissing(ioctl)
	}
	if len(missingStructs) > 0 {
		return fmt.Errorf("expected structs not found: %v", missingStructs)
	}
	if len(missingConstants) > 0 {
		return fmt.Errorf("expected constants not found: %v", missingConstants)
	}

	return nil
}

func main() {
	flag.Parse()
	if err := Main(); err != nil {
		log.Warningf("Error: %v", err)
		os.Exit(1)
	}
}
