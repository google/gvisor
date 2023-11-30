// Copyright 2023 The gVisor Authors.
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

// Package main downloads and installs drivers.
package main

import (
	"context"
	"fmt"
	"os"

	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/tools/gpu/drivers"
)

const (
	installCmdStr       = "install"
	installDescription  = "installs a driver on the host machine"
	checksumCmdStr      = "checksum"
	checksumDescription = "computes the sha256 checksum for a given driver version"
	listCmdStr          = "list"
	listDescription     = "lists the supported drivers"
	checkCmdStr         = "check"
	checkDescription    = "checks that the installed driver is a supported version"
)

var (
	// Install installs a give driver on the host machine.
	installCmd = flag.NewFlagSet(installCmdStr, flag.ContinueOnError)
	latest     = installCmd.Bool("latest", false, "install the latest supported driver")
	version    = installCmd.String("version", "", "version of the driver")

	// Validates all supported driver's checksums of each driver's .run file from the nvidia site.
	checksumCmd = flag.NewFlagSet(checksumCmdStr, flag.ContinueOnError)

	// The list command returns the list of supported drivers from this tool.
	listCmd = flag.NewFlagSet(listCmdStr, flag.ContinueOnError)
	outfile = listCmd.String("outfile", "", "if set, write the list output to this file")

	// The check command checks that the installed driver is a supported version.
	checkCmd = flag.NewFlagSet(checkCmdStr, flag.ContinueOnError)
	// We have this argument because COS has different settings than a default Ubuntu VM.
	cos = checkCmd.Bool("cos", false, "run the test on COS")

	commandSet = map[*flag.FlagSet]string{
		installCmd:  installDescription,
		checksumCmd: checksumDescription,
		listCmd:     listDescription,
		checkCmd:    checkDescription,
	}
)

// printUsage prints the top level usage string.
func printUsage() {
	usage := `Usage: main <command> <flags> ...

Available commands:`
	fmt.Println(usage)
	for _, f := range []*flag.FlagSet{installCmd, checksumCmd, listCmd} {
		fmt.Printf("%s	%s\n", f.Name(), commandSet[f])
		f.PrintDefaults()
	}
}

func logAndExit(f func(string, ...any), s string, v ...any) {
	f(s, v...)
	os.Exit(1)
}

func main() {
	ctx := context.Background()
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case installCmdStr:
		if err := installCmd.Parse(os.Args[2:]); err != nil {
			log.Warningf("%s failed with: %v", installCmdStr, err)
			os.Exit(1)
			logAndExit(log.Warningf, "%s failed with: %v", installCmdStr, err)
		}
		installer, err := drivers.NewInstaller(*version, *latest)
		if err != nil {
			logAndExit(log.Warningf, "Failed to create installer: %v", err.Error())
		}
		if err := installer.MaybeInstall(ctx); err != nil {
			logAndExit(log.Warningf, "Failed to install driver: %v", err.Error())
		}
	case checksumCmdStr:
		if err := checksumCmd.Parse(os.Args[2:]); err != nil {
			logAndExit(log.Warningf, "%s failed with: %v", checksumCmdStr, err)
		}

		for version, storedChecksum := range nvproxy.GetSupportedDriversAndChecksums() {
			checksum, err := drivers.ChecksumDriver(ctx, version.String())
			if err != nil {
				logAndExit(log.Warningf, "error on version %q: %v", version.String(), err)
			}
			if checksum != storedChecksum {
				logAndExit(log.Warningf, "Checksum Mismatch on driver %q got: %q want: %q", version.String(), checksum, storedChecksum)
			}
			log.Infof("Checksum matched on driver %q.", version.String())
		}
	case listCmdStr:
		if err := listCmd.Parse(os.Args[2:]); err != nil {
			logAndExit(log.Warningf, "%s failed with: %v", listCmdStr, err)
		}
		if err := drivers.ListSupportedDrivers(*outfile); err != nil {
			logAndExit(log.Warningf, "Failed to list drivers: %v", err)
		}
	case checkCmdStr:
		if err := checkCmd.Parse(os.Args[2:]); err != nil {
			logAndExit(log.Warningf, "%s failed with: %v", checkCmdStr, err)
		}
		if err := drivers.CheckCurrentDriverCOS(*cos); err != nil {
			logAndExit(log.Warningf, "Failed to check driver: %v", err)
		}
	default:
		printUsage()
		os.Exit(1)
	}
}
