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

// Package user contains methods for resolving filesystem paths based on the
// user and their environment.
package user

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fspath"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

type fileReader struct {
	ctx context.Context
	fd  *vfs.FileDescription
}

func (r *fileReader) Read(buf []byte) (int, error) {
	n, err := r.fd.Read(r.ctx, usermem.BytesIOSequence(buf), vfs.ReadOptions{})
	return int(n), err
}

func getExecUserHome(ctx context.Context, mns *vfs.MountNamespace, uid auth.KUID) (string, error) {
	const defaultHome = "/"

	root := mns.Root()
	root.IncRef()
	defer root.DecRef(ctx)

	creds := auth.CredentialsFromContext(ctx)

	target := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("/etc/passwd"),
	}

	stat, err := root.Mount().Filesystem().VirtualFilesystem().StatAt(ctx, creds, target, &vfs.StatOptions{Mask: linux.STATX_TYPE})
	if err != nil {
		return defaultHome, nil
	}
	if stat.Mask&linux.STATX_TYPE == 0 || stat.Mode&linux.FileTypeMask != linux.ModeRegular {
		return defaultHome, nil
	}

	opts := &vfs.OpenOptions{
		Flags: linux.O_RDONLY,
	}
	fd, err := root.Mount().Filesystem().VirtualFilesystem().OpenAt(ctx, creds, target, opts)
	if err != nil {
		return defaultHome, nil
	}
	defer fd.DecRef(ctx)

	r := &fileReader{
		ctx: ctx,
		fd:  fd,
	}

	homeDir, err := findHomeInPasswd(uint32(uid), r, defaultHome)
	if err != nil {
		return "", err
	}

	return homeDir, nil
}

// MaybeAddExecUserHome returns a new slice with the HOME environment
// variable set if the slice does not already contain it, otherwise it returns
// the original slice unmodified.
func MaybeAddExecUserHome(ctx context.Context, vmns *vfs.MountNamespace, uid auth.KUID, envv []string) ([]string, error) {
	// Check if the envv already contains HOME.
	for _, env := range envv {
		if strings.HasPrefix(env, "HOME=") {
			// We have it. Return the original slice unmodified.
			return envv, nil
		}
	}

	// Read /etc/passwd for the user's HOME directory and set the HOME
	// environment variable as required by POSIX if it is not overridden by
	// the user.
	homeDir, err := getExecUserHome(ctx, vmns, uid)
	if err != nil {
		return nil, fmt.Errorf("error reading exec user: %v", err)
	}
	return append(envv, "HOME="+homeDir), nil
}

// findHomeInPasswd parses a passwd file and returns the given user's home
// directory. This function does it's best to replicate the runc's behavior.
func findHomeInPasswd(uid uint32, passwd io.Reader, defaultHome string) (string, error) {
	s := bufio.NewScanner(passwd)

	for s.Scan() {
		if err := s.Err(); err != nil {
			return "", err
		}

		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}

		// Pull out part of passwd entry. Loosely parse the passwd entry as some
		// passwd files could be poorly written and for compatibility with runc.
		//
		// Per 'man 5 passwd'
		// /etc/passwd contains one line for each user account, with seven
		// fields delimited by colons (“:”). These fields are:
		//
		//	- login name
		//	- optional encrypted password
		//	- numerical user ID
		//	- numerical group ID
		//	- user name or comment field
		//	- user home directory
		//	- optional user command interpreter
		parts := strings.Split(line, ":")

		found := false
		homeDir := ""
		for i, p := range parts {
			switch i {
			case 2:
				parsedUID, err := strconv.ParseUint(p, 10, 32)
				if err == nil && parsedUID == uint64(uid) {
					found = true
				}
			case 5:
				homeDir = p
			}
		}
		if found {
			// NOTE: If the uid is present but the home directory is not
			// present in the /etc/passwd entry we return an empty string. This
			// is, for better or worse, what runc does.
			return homeDir, nil
		}
	}

	return defaultHome, nil
}
