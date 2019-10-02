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

package boot

import (
	"bufio"
	"fmt"
	"io"
	"strconv"
	"strings"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/context"
	"gvisor.dev/gvisor/pkg/sentry/fs"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/usermem"
)

type fileReader struct {
	// Ctx is the context for the file reader.
	Ctx context.Context

	// File is the file to read from.
	File *fs.File
}

// Read implements io.Reader.Read.
func (r *fileReader) Read(buf []byte) (int, error) {
	n, err := r.File.Readv(r.Ctx, usermem.BytesIOSequence(buf))
	return int(n), err
}

// getExecUserHome returns the home directory of the executing user read from
// /etc/passwd as read from the container filesystem.
func getExecUserHome(ctx context.Context, rootMns *fs.MountNamespace, uid auth.KUID) (string, error) {
	// The default user home directory to return if no user matching the user
	// if found in the /etc/passwd found in the image.
	const defaultHome = "/"

	// Open the /etc/passwd file from the dirent via the root mount namespace.
	mnsRoot := rootMns.Root()
	maxTraversals := uint(linux.MaxSymlinkTraversals)
	dirent, err := rootMns.FindInode(ctx, mnsRoot, nil, "/etc/passwd", &maxTraversals)
	if err != nil {
		// NOTE: Ignore errors opening the passwd file. If the passwd file
		// doesn't exist we will return the default home directory.
		return defaultHome, nil
	}
	defer dirent.DecRef()

	// Check read permissions on the file.
	if err := dirent.Inode.CheckPermission(ctx, fs.PermMask{Read: true}); err != nil {
		// NOTE: Ignore permissions errors here and return default root dir.
		return defaultHome, nil
	}

	// Only open regular files. We don't open other files like named pipes as
	// they may block and might present some attack surface to the container.
	// Note that runc does not seem to do this kind of checking.
	if !fs.IsRegular(dirent.Inode.StableAttr) {
		return defaultHome, nil
	}

	f, err := dirent.Inode.GetFile(ctx, dirent, fs.FileFlags{Read: true, Directory: false})
	if err != nil {
		return "", err
	}
	defer f.DecRef()

	r := &fileReader{
		Ctx:  ctx,
		File: f,
	}

	homeDir, err := findHomeInPasswd(uint32(uid), r, defaultHome)
	if err != nil {
		return "", err
	}

	return homeDir, nil
}

// maybeAddExecUserHome returns a new slice with the HOME enviroment variable
// set if the slice does not already contain it, otherwise it returns the
// original slice unmodified.
func maybeAddExecUserHome(ctx context.Context, mns *fs.MountNamespace, uid auth.KUID, envv []string) ([]string, error) {
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
	homeDir, err := getExecUserHome(ctx, mns, uid)
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
		// - login name
		// - optional encrypted password
		// - numerical user ID
		// - numerical group ID
		// - user name or comment field
		// - user home directory
		// - optional user command interpreter
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
