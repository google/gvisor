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
	"fmt"

	"gvisor.dev/gvisor/runsc/flag"
)

// RegisteredArgs is a list of arguments that can be used at the top level of Runsc (ie, before a subcommand)
var RegisteredArgs = []Argument{}

// RegisteredBootArgs is a list of arguments that can be used in the boot subcommand.
var RegisteredBootArgs = []Argument{}

// RegisterArgument adds the argument to the list of top-level args for runsc. The only purpose of this function
// is to add the arg to registeredArgs - it will not read the value provided in the command line until SetArguments()
func RegisterArgument(arg Argument) {
	RegisteredArgs = append(RegisteredArgs, arg)
}

// RegisterBootArgument adds the argument to the list of args for the boot subcommand. The only purpose of this function
// is to add the arg to registeredBootArgs - it will not read the value provided in the command line until SetBootArguments()
func RegisterBootArgument(arg Argument) {
	RegisteredBootArgs = append(RegisteredBootArgs, arg)
}

// SetArguments sets the value provided at the command line for each argument in RegisteredArgs.
// It passes nil for the flagset, since the top-level runsc flagset is globally available and is
// not an object available to passed (see main.go for examples of using the top-level flagset)
func SetArguments() {
	for _, arg := range RegisteredArgs {
		arg.Set(nil)
	}
}

// SetBootArguments sets the value provided at the command line for each argument in RegisteredBootArgs.
// It passes the provided flagset so that each boot argument can add its argument to it, as in cmd/boot.go
func SetBootArguments(f *flag.FlagSet) {
	for _, arg := range RegisteredBootArgs {
		arg.Set(f)
	}
}

// EvaluateArgs calls Evaluate() for all args in RegisteredArgs.
func EvaluateArgs(args ...interface{}) error {
	for _, arg := range RegisteredArgs {
		if err := arg.Evaluate(args...); err != nil {
			return fmt.Errorf("evaluating extra boot arg: %v", err)
		}
	}
	return nil
}

// EvaluateBootArgs calls Evaluate() for all args in RegisteredBootArgs.
func EvaluateBootArgs() error {
	for _, arg := range RegisteredBootArgs {
		if err := arg.Evaluate(); err != nil {
			return fmt.Errorf("evaluating extra boot arg: %v", err)
		}
	}
	return nil
}

// Argument provides an interface for developers to add their own arguments to runsc.
type Argument interface {
	// Set should be implemented such that the argument is added to the list of flags
	// in the relevant flagset, such that when flagset.Parse() is called, the value will
	// be stored in the Argument implementation for later use in Evaluate().
	Set(f *flag.FlagSet)
	// Evaluate should be implemented to perform any any actions that should be executed
	// as a result of the user having specified this value for the arg. Evaluate takes in
	// a variadic interface argument so that any additional information that's needed can
	// be passed as well.
	Evaluate(...interface{}) error
}
