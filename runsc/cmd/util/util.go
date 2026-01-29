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

// Package util groups a bunch of common helper functions used by commands.
package util

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/subcommands"
	specs "github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/runsc/config"
	"gvisor.dev/gvisor/runsc/flag"
)

// SubCommand is an extension of subcommands.Command that allows runsc CLI to
// fetch the OCI spec for the container that is targeted by the command.
type SubCommand interface {
	subcommands.Command

	// FetchSpec returns the container ID, OCI spec associated with the command.
	// If the command does not target a container, it should return "", nil, nil.
	FetchSpec(conf *config.Config, f *flag.FlagSet) (string, *specs.Spec, error)
}

// InternalCommand is an interface for internal commands.
//
// Internal commands are invoked by runsc itself. All of them use the
// --debug-log-fd and --log-fd mechanism. They all return "", nil, nil from
// SubCommand.FetchSpec because they don't need to have the spec as debug log
// file and log files are already created for them. This avoids having to
// re-load the Container struct from local filesystem, read all annotations and
// fix the config via specutils.FixConfig(). They already get the fixed config
// values as conf.ToFlags() is used to create their flags. They don't operate
// on a container so don't even take a container ID as an argument. Some of
// them (like boot and gofer) don't even have access to the host filesystem so
// they can't really open any host files.
type InternalCommand interface {
	InternalFetchSpec() (string, *specs.Spec, error)
}

// InternalSubCommand is a struct that implements FetchSpec for internal
// commands. It should be embedded in internal commands.
type InternalSubCommand struct{}

// FetchSpec implements SubCommand.FetchSpec.
func (i *InternalSubCommand) FetchSpec(*config.Config, *flag.FlagSet) (string, *specs.Spec, error) {
	return i.InternalFetchSpec()
}

// InternalFetchSpec implements InternalCommand.InternalFetchSpec.
func (*InternalSubCommand) InternalFetchSpec() (string, *specs.Spec, error) {
	return "", nil, nil
}

// ErrorLogger is where error messages should be written to. These messages are
// consumed by containerd and show up to users of command line tools,
// like docker/kubectl.
var ErrorLogger io.Writer

type jsonError struct {
	Msg   string    `json:"msg"`
	Level string    `json:"level"`
	Time  time.Time `json:"time"`
}

// Writer writes to log and stdout.
type Writer struct{}

// Write implements io.Writer.
func (i *Writer) Write(data []byte) (n int, err error) {
	log.Infof("%s", data)
	return os.Stdout.Write(data)
}

// Infof writes message to log and stdout.
func Infof(format string, args ...any) {
	log.Infof(format, args...)
	fmt.Printf(format+"\n", args...)
}

// Errorf logs error to containerd log (--log), to stderr, and debug logs. It
// returns subcommands.ExitFailure for convenience with subcommand.Execute()
// methods:
//
//	return Errorf("Danger! Danger!")
func Errorf(format string, args ...any) subcommands.ExitStatus {
	// If runsc is being invoked by docker or cri-o, then we might not have
	// access to stderr, so we log a serious-looking warning in addition to
	// writing to stderr.
	log.Warningf("FATAL ERROR: "+format, args...)
	fmt.Fprintf(os.Stderr, format+"\n", args...)

	if ErrorLogger != nil {
		j := jsonError{
			Msg:   fmt.Sprintf(format, args...),
			Level: "error",
			Time:  time.Now(),
		}
		b, err := json.Marshal(j)
		if err != nil {
			panic(err)
		}
		_, _ = ErrorLogger.Write(b)
	}

	return subcommands.ExitFailure
}

// Fatalf logs the same way as Errorf() does, plus *exits* the process.
func Fatalf(format string, args ...any) {
	Errorf(format, args...)
	// Return an error that is unlikely to be used by the application.
	os.Exit(128)
}
