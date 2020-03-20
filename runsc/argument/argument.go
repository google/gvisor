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

// Package argument provides mechanisms for developers to specify extra arguments
// for the boot subcommand that are not explicitly written in boot.go. This is a
// fairly restrictive pipeline only meant to allow for the specification of top-level
// runsc args that result in additional arguments being passed to the boot subcommand;
// it may be generalized further in the future.
package argument

import (
	"os"

	"gvisor.dev/gvisor/runsc/flag"
)

// RegisteredArgs is a list of arguments that can be set in runsc or a subcommand of runsc.
var RegisteredArgs = []Argument{}

// RegisterArgument adds the argument to the list of arguments that should be set. The only purpose of this function
// is to add the arg to registeredArgs - the value provided in the command line will not be read until SetRegisteredArgs()
func RegisterArgument(arg Argument) {
	RegisteredArgs = append(RegisteredArgs, arg)
}

// SetRegisteredArgs sets the value provided at the command line for each argument in RegisteredArgs.
// Take note that nil may be passed into this function, so arguments should perform appropriate nil checks.
func SetRegisteredArgs(f *flag.FlagSet) {
	for _, arg := range RegisteredArgs {
		arg.Set(f)
	}
}

// Argument provides an interface for developers to add their own arguments to runsc.
type Argument interface {
	// Set should be implemented such that the argument is added to the list of flags
	// in the relevant flagset, so that when flagset.Parse() is called, the value will
	// be stored in the Argument implementation for later use in OnSandboxProcessCreate() or OnBoot().
	Set(f *flag.FlagSet)
	// OnCreateSandboxProcess will be evaluated near the end of createSandboxProcess(). Any strings returned
	// in extraArgs will be appended to cmd.Args, and any files returned in extraFiles will be appended to
	// cmd.ExtraFiles. Implementations are responsible for updating nextFD appropriately.
	OnCreateSandboxProcess(id string, nextFD *int) (extraArgs []string, extraFiles []*os.File, err error)
	// OnBoot will be evaluated when a new kernel loader is created.
	OnBoot() error
}
