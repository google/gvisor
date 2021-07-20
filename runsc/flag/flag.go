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

//go:build go1.1
// +build go1.1

// Package flag wraps flag primitives.
package flag

import (
	"flag"
)

// FlagSet is an alias for flag.FlagSet.
type FlagSet = flag.FlagSet

// Aliases for flag functions.
var (
	Bool        = flag.Bool
	CommandLine = flag.CommandLine
	Int         = flag.Int
	NewFlagSet  = flag.NewFlagSet
	Parse       = flag.Parse
	String      = flag.String
	Uint        = flag.Uint
	Var         = flag.Var
)

// ContinueOnError is an alias for flag.ContinueOnError.
const ContinueOnError = flag.ContinueOnError

// Get returns the flag's underlying object.
func Get(v flag.Value) interface{} {
	return v.(flag.Getter).Get()
}
