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

	root := mns.Root(ctx)
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

func findUIDGIDInPasswd(passwd io.Reader, user string) (auth.KUID, auth.KGID, error) {
	defaultUID := auth.KUID(auth.OverflowUID)
	defaultGID := auth.KGID(auth.OverflowGID)
	uid := defaultUID
	gid := defaultGID

	// Per 'man 5 passwd'
	// /etc/passwd contains one line for each user account, with seven
	// fields delimited by colons (“:”). These fields are:
	//
	//	- login name
	//	- optional encrypted password
	//	- numerical user ID
	//	- numerical group ID
	//	- Gecos field
	//	- user home directory
	//	- optional user command interpreter
	const (
		numFields = 7
		userIdx   = 0
		passwdIdx = 1
		uidIdx    = 2
		gidIdx    = 3
		gecosIdx  = 4
		shellIdx  = 6
	)
	usergroup := strings.SplitN(user, ":", 2)
	uStringOrID := usergroup[0]

	// Check if we have a uid or string for user.
	idxToMatch := uidIdx
	_, err := strconv.Atoi(uStringOrID)
	if err != nil {
		idxToMatch = userIdx
	}

	s := bufio.NewScanner(passwd)
	for s.Scan() {
		if err := s.Err(); err != nil {
			return defaultUID, defaultGID, err
		}

		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		if len(parts) != numFields {
			// Return error if the format is invalid.
			return defaultUID, defaultGID, fmt.Errorf("invalid line found in /etc/passwd, there should be 7 fields but found %v", len(parts))
		}
		for i := 0; i < numFields; i++ {
			// The password, GECOS and user command interpreter fields are
			// optional, no need to check if they are empty.
			if i == passwdIdx || i == shellIdx || i == gecosIdx {
				continue
			}
			if parts[i] == "" {
				// Return error if the format is invalid.
				return defaultUID, defaultGID, fmt.Errorf("invalid line found in /etc/passwd, field[%v] is empty", i)
			}
		}

		if parts[idxToMatch] == uStringOrID {
			parseUID, err := strconv.ParseUint(parts[uidIdx], 10, 32)
			if err != nil {
				return defaultUID, defaultGID, err
			}
			parseGID, err := strconv.ParseUint(parts[gidIdx], 10, 32)
			if err != nil {
				return defaultUID, defaultGID, err
			}

			if uid != defaultUID || gid != defaultGID {
				return defaultUID, defaultGID, fmt.Errorf("multiple matches for the user: %v", user)
			}
			uid = auth.KUID(parseUID)
			gid = auth.KGID(parseGID)
		}
	}
	if uid == defaultUID || gid == defaultGID {
		return defaultUID, defaultGID, fmt.Errorf("couldn't retrieve UID/GID from user: %v", user)
	}
	return uid, gid, nil
}

func getExecUIDGID(ctx context.Context, mns *vfs.MountNamespace, user string) (auth.KUID, auth.KGID, error) {
	root := mns.Root(ctx)
	defer root.DecRef(ctx)

	creds := auth.CredentialsFromContext(ctx)

	target := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse("/etc/passwd"),
	}

	fd, err := root.Mount().Filesystem().VirtualFilesystem().OpenAt(ctx, creds, target, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		return auth.KUID(auth.OverflowUID), auth.KGID(auth.OverflowGID), fmt.Errorf("couldn't retrieve UID/GID from user: %v, err: %v", user, err)
	}
	defer fd.DecRef(ctx)

	r := &fileReader{
		ctx: ctx,
		fd:  fd,
	}

	return findUIDGIDInPasswd(r, user)
}

// GetExecUIDGIDFromUser retrieves the UID and GID from /etc/passwd file for
// the given user.
func GetExecUIDGIDFromUser(ctx context.Context, vmns *vfs.MountNamespace, user string) (auth.KUID, auth.KGID, error) {
	// Read /etc/passwd and retrieve the UID/GID based on the user string.
	uid, gid, err := getExecUIDGID(ctx, vmns, user)
	if err != nil {
		return uid, gid, fmt.Errorf("error reading /etc/passwd: %v", err)
	}
	return uid, gid, nil
}
