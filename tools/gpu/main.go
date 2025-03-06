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
	"gvisor.dev/gvisor/pkg/sentry/devices/nvproxy/nvconf"
	"gvisor.dev/gvisor/runsc/flag"
	"gvisor.dev/gvisor/tools/gpu/drivers"
)

const (
	installCmdStr               = "install"
	installDescription          = "installs a driver on the host machine"
	checksumCmdStr              = "checksum"
	checksumDescription         = "computes the sha256 checksum for a given driver version"
	validateChecksumCmdStr      = "validate_checksum"
	validateChecksumDescription = "validates the checksum of all supported drivers"
	listCmdStr                  = "list"
	listDescription             = "lists the supported drivers"
)

var (
	// Install installs a give driver on the host machine.
	installCmd = flag.NewFlagSet(installCmdStr, flag.ContinueOnError)
	latest     = installCmd.Bool("latest", false, "install the latest supported driver")
	version    = installCmd.String("version", "", "version of the driver")

	// Computes the sha256 checksum for a given driver's .run file from the nvidia site.
	checksumCmd     = flag.NewFlagSet(checksumCmdStr, flag.ContinueOnError)
	checksumVersion = checksumCmd.String("version", "", "version of the driver")

	// Validates all supported driver's checksums of each driver's .run file from the nvidia site.
	validateChecksumCmd = flag.NewFlagSet(validateChecksumCmdStr, flag.ContinueOnError)

	// The list command returns the list of supported drivers from this tool.
	listCmd = flag.NewFlagSet(listCmdStr, flag.ContinueOnError)
	outfile = listCmd.String("outfile", "", "if set, write the list output to this file")

	commandSet = map[*flag.FlagSet]string{
		installCmd:          installDescription,
		checksumCmd:         checksumDescription,
		validateChecksumCmd: validateChecksumDescription,
		listCmd:             listDescription,
	}
)

// printUsage prints the top level usage string.
func printUsage() {
	usage := `Usage: main <command> <flags> ...

Available commands:`
	fmt.Println(usage)
	for _, f := range []*flag.FlagSet{installCmd, checksumCmd, validateChecksumCmd, listCmd} {
		fmt.Printf("%s	%s\n", f.Name(), commandSet[f])
		f.PrintDefaults()
	}
}

func main() {
	ctx := context.Background()
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}
	nvproxy.Init()
	switch os.Args[1] {
	case installCmdStr:
		if err := installCmd.Parse(os.Args[2:]); err != nil {
			log.Warningf("%s failed with: %v", installCmdStr, err)
			os.Exit(1)
		}
		installer, err := drivers.NewInstaller(*version, *latest)
		if err != nil {
			log.Warningf("Failed to create installer: %v", err.Error())
			os.Exit(1)
		}
		if err := installer.MaybeInstall(ctx); err != nil {
			log.Warningf("Failed to install driver: %v", err.Error())
			os.Exit(1)
		}
	case checksumCmdStr:
		if err := checksumCmd.Parse(os.Args[2:]); err != nil {
			log.Warningf("%s failed with: %v", checksumCmdStr, err)
			os.Exit(1)
		}

		checksum, err := drivers.ChecksumDriver(ctx, *checksumVersion)
		if err != nil {
			log.Warningf("Failed to compute checksum: %v", err)
			os.Exit(1)
		}
		fmt.Printf("Checksum: %q\n", checksum)
	case validateChecksumCmdStr:
		if err := validateChecksumCmd.Parse(os.Args[2:]); err != nil {
			log.Warningf("%s failed with: %v", validateChecksumCmdStr, err)
			os.Exit(1)
		}

		nvproxy.ForEachSupportDriver(func(version nvconf.DriverVersion, checksum string) {
			wantChecksum, err := drivers.ChecksumDriver(ctx, version.String())
			if err != nil {
				log.Warningf("error on version %q: %v", version.String(), err)
				return
			}
			if checksum != wantChecksum {
				log.Warningf("Checksum mismatch on driver %q got: %q want: %q", version.String(), checksum, wantChecksum)
				return
			}
			log.Infof("Checksum matched on driver %q.", version.String())
		})
	case listCmdStr:
		if err := listCmd.Parse(os.Args[2:]); err != nil {
			log.Warningf("%s failed with: %v", listCmdStr, err)
			os.Exit(1)
		}
		if err := drivers.ListSupportedDrivers(*outfile); err != nil {
			log.Warningf("Failed to list drivers: %v", err)
			os.Exit(1)
		}
	default:
		printUsage()
		os.Exit(1)
	}
}
