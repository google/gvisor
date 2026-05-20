// Copyright 2025 The gVisor Authors.
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

// Binary checkpointgofer implements the checkpoint gofer, which provides
// remote checkpoint file access.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/google/subcommands"
	"golang.org/x/oauth2"
	"gvisor.dev/gvisor/pkg/sentry/state/stateipc"
	"gvisor.dev/gvisor/pkg/unet"
	"gvisor.dev/gvisor/pkg/urpc"
	"gvisor.dev/gvisor/runsc/checkpointgofer/gcs"
	"gvisor.dev/gvisor/runsc/cli"
	"gvisor.dev/gvisor/runsc/cmd/util"
	"gvisor.dev/gvisor/runsc/flag"
)

// GCSOptions holds options that configure a checkpoint gofer to access GCS.
type GCSOptions struct {
	// If Token is non-empty, the checkpoint gofer will use it for
	// authentication.
	//
	// Otherwise, the checkpoint gofer will use application default
	// credentials.
	Token *oauth2.Token `json:"token,omitzero"`

	// Bucket is the GCS bucket containing checkpoint files.
	Bucket string `json:"bucket"`

	// ObjectPrefix is prepended to checkpoint file names to form GCS object
	// names. Note that ObjectPrefix is prepended as a string, not a path, so
	// if ObjectPrefix does not have a trailing "/", no "/" will be inserted
	// between ObjectPrefix and the filename.
	ObjectPrefix string `json:"object_prefix"`

	// ParallelCompositeUpload controls whether parallel composite upload is
	// used for writing the pages file. Valid values are:
	// - "safe": enable parallel composite upload if safe
	// - "disable": disable parallel composite upload unconditionally
	// - "force": enable parallel composite upload unconditionally
	ParallelCompositeUpload string `json:"parallel_composite_upload,omitzero"`
}

// checkpointGoferCmd implements subcommands.Command for the checkpoint gofer.
type checkpointGoferCmd struct {
	util.InternalSubCommand

	allowCheckpointReads    bool
	allowCheckpointWrites   bool
	allowFSCheckpointReads  bool
	allowFSCheckpointWrites bool

	sockFD    int
	gcsOptsFD int
}

// Name implements subcommands.Command.Name.
func (*checkpointGoferCmd) Name() string {
	return "checkpointgofer"
}

// Synopsis implements subcommands.Command.Synopsis.
func (*checkpointGoferCmd) Synopsis() string {
	return "runs process for remote checkpoint file access"
}

// Usage implements subcommands.Command.Usage.
func (*checkpointGoferCmd) Usage() string {
	return "[-allow-checkpoint-reads|-allow-checkpoint-writes|-allow-fscheckpoint-reads|-allow-fscheckpoint-writes] -sock-fd=<socket fd> -gcs-opts-fd=<options fd>\n"
}

// SetFlags implements subcommands.Command.SetFlags.
func (cmd *checkpointGoferCmd) SetFlags(f *flag.FlagSet) {
	f.BoolVar(&cmd.allowCheckpointReads, "allow-checkpoint-reads", false, "enable reading checkpoint files")
	f.BoolVar(&cmd.allowCheckpointWrites, "allow-checkpoint-writes", false, "enable writing checkpoint files")
	f.BoolVar(&cmd.allowFSCheckpointReads, "allow-fscheckpoint-reads", false, "enable reading filesystem checkpoint files")
	f.BoolVar(&cmd.allowFSCheckpointWrites, "allow-fscheckpoint-writes", false, "enable writing filesystem checkpoint files")
	f.IntVar(&cmd.sockFD, "sock-fd", -1, "FD for a Unix domain socket that is connected to the sentry")
	f.IntVar(&cmd.gcsOptsFD, "gcs-opts-fd", -1, "FD for a file containing GCSOptions in JSON")
}

// Execute implements subcommands.Command.Execute.
func (cmd *checkpointGoferCmd) Execute(ctx context.Context, f *flag.FlagSet, args ...any) subcommands.ExitStatus {
	if (!cmd.allowCheckpointReads && !cmd.allowCheckpointWrites && !cmd.allowFSCheckpointReads && !cmd.allowFSCheckpointWrites) || cmd.sockFD < 0 || cmd.gcsOptsFD < 0 {
		f.Usage()
		return subcommands.ExitUsageError
	}

	sock, err := unet.NewSocket(cmd.sockFD)
	if err != nil {
		util.Fatalf("Failed to construct unet.Socket: %v", err)
	}

	gcsOptsFile := os.NewFile(uintptr(cmd.gcsOptsFD), "checkpointgofer.GCSOptions.json")
	var gcsOpts GCSOptions
	if err := json.NewDecoder(gcsOptsFile).Decode(&gcsOpts); err != nil {
		util.Fatalf("Failed to decode options: %v", err)
	}
	gcsOptsFile.Close()
	if err := cmd.runGCS(ctx, sock, &gcsOpts); err != nil {
		util.Fatalf("%v", err)
	}

	util.Infof("Server stopped, exiting")
	return subcommands.ExitSuccess
}

// runGCS runs the checkpoint gofer for GCS access on the given socket. It does
// not return until the client disconnects or a fatal error occurs.
func (cmd *checkpointGoferCmd) runGCS(ctx context.Context, sock *unet.Socket, opts *GCSOptions) error {
	if len(opts.Bucket) == 0 {
		return fmt.Errorf("bucket must be specified")
	}

	gcsfsOpts := gcs.FileServerOptions{
		AllowCheckpointReads:    cmd.allowCheckpointReads,
		AllowCheckpointWrites:   cmd.allowCheckpointWrites,
		AllowFSCheckpointReads:  cmd.allowFSCheckpointReads,
		AllowFSCheckpointWrites: cmd.allowFSCheckpointWrites,
		Bucket:                  opts.Bucket,
		ObjectPrefix:            opts.ObjectPrefix,
	}
	if opts.Token != nil {
		gcsfsOpts.TokenSource = oauth2.StaticTokenSource(opts.Token)
	}
	switch opts.ParallelCompositeUpload {
	case "", "safe":
		gcsfsOpts.ParallelCompositeUpload = gcs.ParallelCompositeUploadSafe
	case "disable":
		gcsfsOpts.ParallelCompositeUpload = gcs.ParallelCompositeUploadDisable
	case "force":
		gcsfsOpts.ParallelCompositeUpload = gcs.ParallelCompositeUploadForce
	default:
		return fmt.Errorf("unknown parallel_composite_upload value %q", opts.ParallelCompositeUpload)
	}

	gcsfs, err := gcs.NewFileServer(ctx, &gcsfsOpts)
	if err != nil {
		return fmt.Errorf("failed to construct GCS file server: %w", err)
	}
	afs, err := stateipc.NewAsyncFileServer(gcsfs)
	if err != nil {
		return fmt.Errorf("failed to construct stateipc server: %w", err)
	}
	server := urpc.NewServer()
	server.Register(afs)
	server.Handle(sock)
	return nil
}

// main is the binary's entry point.
func main() {
	cli.Run(map[util.SubCommand]string{
		new(checkpointGoferCmd): "",
	}, nil)
}
