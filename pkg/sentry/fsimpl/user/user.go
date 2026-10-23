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
	"gvisor.dev/gvisor/pkg/log"
	"gvisor.dev/gvisor/pkg/sentry/kernel/auth"
	"gvisor.dev/gvisor/pkg/sentry/vfs"
	"gvisor.dev/gvisor/pkg/usermem"
)

const (
	defaultUID = auth.KUID(0)
	defaultGID = auth.KGID(0)
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

func openFile(ctx context.Context, mns *vfs.MountNamespace, path string) (*vfs.FileDescription, error) {
	log.Infof("Opening %q", path)
	root := mns.Root(ctx)
	defer root.DecRef(ctx)
	creds := auth.CredentialsFromContext(ctx)

	target := &vfs.PathOperation{
		Root:  root,
		Start: root,
		Path:  fspath.Parse(path),
	}
	fd, err := root.Mount().Filesystem().VirtualFilesystem().OpenAt(ctx, creds, target, &vfs.OpenOptions{Flags: linux.O_RDONLY})
	if err != nil {
		log.Warningf("Failed to open %q, error: %v", path, err)
		return nil, err
	}

	return fd, nil
}

// isNumericID distinguishes signed decimal IDs from user and group names.
func isNumericID(id string) bool {
	if len(id) > 0 && (id[0] == '+' || id[0] == '-') {
		id = id[1:]
	}
	return id != "" && strings.Trim(id, "0123456789") == ""
}

func parseID(id string) (uint32, error) {
	n, err := strconv.ParseUint(id, 10, 32)
	if err != nil {
		return 0, err
	}
	if n == auth.NoID {
		return 0, fmt.Errorf("ID %q is reserved: %w", id, strconv.ErrRange)
	}
	return uint32(n), nil
}

// FindGroupInGroupFile parses a group file and returns the given group's
// gid. If the gid is a number, we don't need to read the file.
//
// If we don't find the group, we return 0. Invalid numeric IDs return an error.
func FindGroupInGroupFile(group io.Reader, gidString string) (auth.KGID, error) {
	// gid is a number, we don't need to read the file.
	if isNumericID(gidString) {
		gid, err := parseID(strings.TrimPrefix(gidString, "+"))
		if err != nil {
			return 0, fmt.Errorf("invalid group %q: %w", gidString, err)
		}
		return auth.KGID(gid), nil
	}

	// Group file format:
	// group_name:password:gid:<user1,user2,user3>
	const (
		grpIdx    = 0
		passwdIdx = 1
		gidIdx    = 2
	)

	s := bufio.NewScanner(group)
	for s.Scan() {
		if err := s.Err(); err != nil {
			return defaultGID, nil
		}
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, ":")
		if parts[grpIdx] == gidString {
			if len(parts) <= gidIdx {
				return 0, fmt.Errorf("missing GID for group %q: %w", gidString, strconv.ErrSyntax)
			}
			gid, err := parseID(strings.TrimPrefix(parts[gidIdx], "+"))
			if err != nil {
				return 0, fmt.Errorf("invalid GID for group %q: %w", gidString, err)
			}
			return auth.KGID(gid), nil
		}
	}

	// Not found, return 0
	return defaultGID, nil
}

// FindUIDGIDInPasswd parses a passwd file and returns the given user's uid and gid.
// Invalid numeric requests or selected records return an error.
func FindUIDGIDInPasswd(passwd io.Reader, user string) (auth.KUID, auth.KGID, error) {
	fallbackUID, fallbackGID, err := getDefaultUIDGID(user)
	if err != nil {
		return 0, 0, err
	}

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
	if !isNumericID(uStringOrID) {
		idxToMatch = userIdx
	}

	s := bufio.NewScanner(passwd)
	for s.Scan() {
		if err := s.Err(); err != nil {
			return fallbackUID, fallbackGID, nil
		}

		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Split(line, ":")
		matched := len(parts) > idxToMatch && parts[idxToMatch] == uStringOrID
		if len(parts) != numFields {
			if matched {
				return 0, 0, fmt.Errorf("invalid passwd record for user %q: %w", uStringOrID, strconv.ErrSyntax)
			}
			// If format is invalid, return default values.
			return fallbackUID, fallbackGID, nil
		}
		for i := 0; i < numFields; i++ {
			// The password, GECOS and user command interpreter fields are
			// optional, no need to check if they are empty.
			if i == passwdIdx || i == shellIdx || i == gecosIdx {
				continue
			}
			if parts[i] == "" {
				if matched {
					return 0, 0, fmt.Errorf("empty field %d for user %q: %w", i, uStringOrID, strconv.ErrSyntax)
				}
				// If format is invalid, return default values.
				return fallbackUID, fallbackGID, nil
			}
		}

		if matched {
			uid, err := parseID(parts[uidIdx])
			if err != nil {
				return 0, 0, fmt.Errorf("invalid UID for user %q: %w", uStringOrID, err)
			}
			gid, err := parseID(parts[gidIdx])
			if err != nil {
				return 0, 0, fmt.Errorf("invalid GID for user %q: %w", uStringOrID, err)
			}
			return auth.KUID(uid), auth.KGID(gid), nil
		}
	}

	return fallbackUID, fallbackGID, nil
}

func getDefaultUIDGID(user string) (auth.KUID, auth.KGID, error) {
	usergroup := strings.SplitN(user, ":", 2)
	uid := defaultUID
	gid := defaultGID

	// resolving uid. If it is numeric, set uid to the int value, if not keep it to 0.
	if isNumericID(usergroup[0]) {
		u, err := parseID(strings.TrimPrefix(usergroup[0], "+"))
		if err != nil {
			return 0, 0, fmt.Errorf("invalid user %q: %w", usergroup[0], err)
		}
		uid = auth.KUID(u)
	}

	// if we do have a group, try to get the numeric value. If numeric, set gid to the int value, if
	// not keep it to 0.
	if len(usergroup) == 2 && isNumericID(usergroup[1]) {
		g, err := parseID(strings.TrimPrefix(usergroup[1], "+"))
		if err != nil {
			return 0, 0, fmt.Errorf("invalid group %q: %w", usergroup[1], err)
		}
		gid = auth.KGID(g)
	}

	return uid, gid, nil
}

// GetExecUIDGIDFromUser retrieves the UID and GID from /etc/passwd and /etc/group
// for the given user. Invalid numeric requests or selected records return an
// error; missing names and files retain the default UID/GID behavior.
func GetExecUIDGIDFromUser(ctx context.Context, mns *vfs.MountNamespace, user string) (auth.KUID, auth.KGID, error) {
	// Validate both requested IDs before a missing file can select a fallback.
	uid, gid, err := getDefaultUIDGID(user)
	if err != nil {
		return 0, 0, err
	}
	fd, err := openFile(ctx, mns, "/etc/passwd")
	if err != nil {
		return uid, gid, nil
	}
	defer fd.DecRef(ctx)

	r := &fileReader{
		ctx: ctx,
		fd:  fd,
	}
	// Resolve the user's primary group before applying any explicit group override.
	uid, gid, err = FindUIDGIDInPasswd(r, user)
	if err != nil {
		return 0, 0, err
	}
	usergroup := strings.SplitN(user, ":", 2)

	// If we have a group id string, try to resolve it.
	if len(usergroup) == 2 {
		fdg, err := openFile(ctx, mns, "/etc/group")
		if err != nil {
			return uid, defaultGID, nil
		}
		defer fdg.DecRef(ctx)
		r = &fileReader{
			ctx: ctx,
			fd:  fdg,
		}
		gid, err = FindGroupInGroupFile(r, usergroup[1])
		if err != nil {
			return 0, 0, err
		}
	}
	return uid, gid, nil
}
