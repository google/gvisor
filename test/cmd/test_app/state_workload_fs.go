// Copyright 2026 The gVisor Authors.
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

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// fsProbeDirName is the directory that an fsProbe creates in the filesystem
// it exercises.
const fsProbeDirName = "fsprobe"

// fsProbeLogName is the name of the append-only log file in fsProbeDirName.
// Its expected contents after a run of n hops is given by fsProbeLog.
const fsProbeLogName = "log"

// fsProbeLog returns the expected contents of the log file of the fsProbe
// named name after the given number of verified hops.
func fsProbeLog(name string, hops int) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "fsprobe:%s\n", name)
	for hop := 0; hop < hops; hop++ {
		fmt.Fprintf(&b, "hop=%d\nverified=%d\n", hop, hop)
	}
	return b.Bytes()
}

// fsProbe holds open files, a shared file mapping, and directory state in one
// filesystem (tmpfs, host bind mount, or root overlay) that must survive
// checkpoint/restore.
type fsProbe struct {
	name string
	dir  string
	// allowUnlinked is true if open unlinked files are expected to survive
	// checkpoint/restore in this filesystem.
	allowUnlinked bool

	// logFile is the log file, kept open with O_APPEND.
	logFile *os.File
	// wantLog is the expected content of the log file.
	wantLog []byte
	// readFile is the log file opened read-only, at offset readOff.
	readFile *os.File
	readOff  int64
	// mapFile is backing a MAP_SHARED mapping, mapping.
	mapFile *os.File
	mapping []byte
	// wantMap is the expected content of mapping.
	wantMap []byte
	// unlinked is an open file that has been unlinked, with content
	// wantUnlinked.
	unlinked     *os.File
	wantUnlinked string
}

func newFSProbe(name, root string, allowUnlinked bool) (*fsProbe, error) {
	p := &fsProbe{
		name:          name,
		dir:           filepath.Join(root, fsProbeDirName),
		allowUnlinked: allowUnlinked,
	}
	if err := os.MkdirAll(p.dir, 0755); err != nil {
		return nil, fmt.Errorf("MkdirAll(%q): %w", p.dir, err)
	}
	logPath := filepath.Join(p.dir, fsProbeLogName)
	var err error
	if p.logFile, err = os.OpenFile(logPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC|os.O_APPEND, 0644); err != nil {
		return nil, fmt.Errorf("OpenFile(%q): %w", logPath, err)
	}
	if err := p.appendLog(fmt.Sprintf("fsprobe:%s\n", name)); err != nil {
		return nil, err
	}
	if p.readFile, err = os.Open(logPath); err != nil {
		return nil, fmt.Errorf("Open(%q): %w", logPath, err)
	}
	mapPath := filepath.Join(p.dir, "map")
	if p.mapFile, err = os.OpenFile(mapPath, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644); err != nil {
		return nil, fmt.Errorf("OpenFile(%q): %w", mapPath, err)
	}
	if err := p.mapFile.Truncate(shmPageSize); err != nil {
		return nil, fmt.Errorf("Truncate(%q): %w", mapPath, err)
	}
	if p.mapping, err = unix.Mmap(int(p.mapFile.Fd()), 0, shmPageSize, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED); err != nil {
		return nil, fmt.Errorf("Mmap(%q): %w", mapPath, err)
	}
	return p, nil
}

func (p *fsProbe) close() {
	if p.mapping != nil {
		unix.Munmap(p.mapping)
	}
	for _, f := range []*os.File{p.logFile, p.readFile, p.mapFile, p.unlinked} {
		if f != nil {
			f.Close()
		}
	}
}

func (p *fsProbe) appendLog(s string) error {
	if _, err := p.logFile.WriteString(s); err != nil {
		return fmt.Errorf("%s: append to log: %w", p.name, err)
	}
	p.wantLog = append(p.wantLog, s...)
	return nil
}

func renamedName(hop int) string { return fmt.Sprintf("renamed-%d", hop) }
func hopDirName(hop int) string  { return fmt.Sprintf("dir-%d", hop) }

// prepare mutates the filesystem state before the checkpoint of hop.
func (p *fsProbe) prepare(hop int) error {
	if err := p.appendLog(fmt.Sprintf("hop=%d\n", hop)); err != nil {
		return err
	}
	// Leave the read-only handle partway into the log.
	p.readOff = int64(len(p.wantLog)) - 2
	if _, err := p.readFile.Seek(p.readOff, io.SeekStart); err != nil {
		return fmt.Errorf("%s: Seek log: %w", p.name, err)
	}
	p.wantMap = deterministicPattern("fsprobe-map-"+p.name, hop, shmPageSize)
	copy(p.mapping, p.wantMap)

	// Rename the previous hop's file, and create a directory with a file.
	dst := filepath.Join(p.dir, renamedName(hop))
	if hop == 0 {
		if err := os.WriteFile(dst, []byte(p.name), 0644); err != nil {
			return fmt.Errorf("%s: WriteFile(%q): %w", p.name, dst, err)
		}
	} else if err := os.Rename(filepath.Join(p.dir, renamedName(hop-1)), dst); err != nil {
		return fmt.Errorf("%s: Rename to %q: %w", p.name, dst, err)
	}
	hopDir := filepath.Join(p.dir, hopDirName(hop))
	if err := os.Mkdir(hopDir, 0755); err != nil {
		return fmt.Errorf("%s: Mkdir(%q): %w", p.name, hopDir, err)
	}
	if err := os.WriteFile(filepath.Join(hopDir, "f"), []byte(hopDir), 0644); err != nil {
		return fmt.Errorf("%s: WriteFile in %q: %w", p.name, hopDir, err)
	}

	if p.allowUnlinked {
		if p.unlinked != nil {
			p.unlinked.Close()
		}
		path := filepath.Join(p.dir, fmt.Sprintf("unlinked-%d", hop))
		f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
		if err != nil {
			return fmt.Errorf("%s: OpenFile(%q): %w", p.name, path, err)
		}
		p.unlinked = f
		p.wantUnlinked = fmt.Sprintf("%s-unlinked-%d", p.name, hop)
		if _, err := f.WriteString(p.wantUnlinked); err != nil {
			return fmt.Errorf("%s: write unlinked: %w", p.name, err)
		}
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("%s: Remove(%q): %w", p.name, path, err)
		}
	}
	return nil
}

// verify checks the filesystem state after the restore of hop, and records
// the verification in the log.
func (p *fsProbe) verify(hop int) error {
	logPath := filepath.Join(p.dir, fsProbeLogName)
	if got, err := os.ReadFile(logPath); err != nil || !bytes.Equal(got, p.wantLog) {
		return fmt.Errorf("%s: ReadFile(%q) = (%q, %v), want %q", p.name, logPath, got, err, p.wantLog)
	}
	if off, err := p.readFile.Seek(0, io.SeekCurrent); err != nil || off != p.readOff {
		return fmt.Errorf("%s: read handle offset = (%d, %v), want %d", p.name, off, err, p.readOff)
	}
	if got, err := io.ReadAll(p.readFile); err != nil || !bytes.Equal(got, p.wantLog[p.readOff:]) {
		return fmt.Errorf("%s: read from saved offset = (%q, %v), want %q", p.name, got, err, p.wantLog[p.readOff:])
	}
	if !bytes.Equal(p.mapping, p.wantMap) {
		return fmt.Errorf("%s: shared file mapping contents changed across restore", p.name)
	}
	buf := make([]byte, shmPageSize)
	if _, err := p.mapFile.ReadAt(buf, 0); err != nil || !bytes.Equal(buf, p.wantMap) {
		return fmt.Errorf("%s: mapped file read mismatch (err=%v)", p.name, err)
	}
	probe := []byte{byte(0x5a ^ hop)}
	if _, err := p.mapFile.WriteAt(probe, 11); err != nil {
		return fmt.Errorf("%s: mapped file WriteAt: %w", p.name, err)
	}
	if p.mapping[11] != probe[0] {
		return fmt.Errorf("%s: MAP_SHARED coherence lost: mapping[11]=%#x, want %#x", p.name, p.mapping[11], probe[0])
	}
	p.wantMap[11] = probe[0]

	entries, err := os.ReadDir(p.dir)
	if err != nil {
		return fmt.Errorf("%s: ReadDir(%q): %w", p.name, p.dir, err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	for i := 0; i <= hop; i++ {
		if !slices.Contains(names, hopDirName(i)) {
			return fmt.Errorf("%s: %q missing from %v", p.name, hopDirName(i), names)
		}
		f := filepath.Join(p.dir, hopDirName(i), "f")
		if got, err := os.ReadFile(f); err != nil || string(got) != filepath.Dir(f) {
			return fmt.Errorf("%s: ReadFile(%q) = (%q, %v)", p.name, f, got, err)
		}
	}
	if !slices.Contains(names, renamedName(hop)) || (hop > 0 && slices.Contains(names, renamedName(hop-1))) {
		return fmt.Errorf("%s: rename to %q not preserved: %v", p.name, renamedName(hop), names)
	}
	for _, n := range names {
		if strings.HasPrefix(n, "unlinked-") {
			return fmt.Errorf("%s: unlinked file %q reappeared", p.name, n)
		}
	}

	if p.allowUnlinked {
		if _, err := p.unlinked.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("%s: Seek unlinked: %w", p.name, err)
		}
		if got, err := io.ReadAll(p.unlinked); err != nil || string(got) != p.wantUnlinked {
			return fmt.Errorf("%s: unlinked file read = (%q, %v), want %q", p.name, got, err, p.wantUnlinked)
		}
		if _, err := p.unlinked.WriteString(":post-restore"); err != nil {
			return fmt.Errorf("%s: write unlinked post-restore: %w", p.name, err)
		}
		p.wantUnlinked += ":post-restore"
	}

	// New files can be created after restore.
	fresh := filepath.Join(p.dir, fmt.Sprintf("fresh-%d", hop))
	if err := os.WriteFile(fresh, []byte(p.name), 0644); err != nil {
		return fmt.Errorf("%s: WriteFile(%q) post-restore: %w", p.name, fresh, err)
	}
	return p.appendLog(fmt.Sprintf("verified=%d\n", hop))
}
