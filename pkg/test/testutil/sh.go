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

package testutil

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/kr/pty"
	"golang.org/x/sys/unix"
)

// Prompt is used as shell prompt.
// It is meant to be unique enough to not be seen in command outputs.
const Prompt = "PROMPT> "

// Simplistic shell string escape.
func shellEscape(s string) string {
	// specialChars is used to determine whether s needs quoting at all.
	const specialChars = "\\'\"`${[|&;<>()*?! \t\n"
	// If s needs quoting, escapedChars is the set of characters that are
	// escaped with a backslash.
	const escapedChars = "\\\"$`"
	if len(s) == 0 {
		return "''"
	}
	if !strings.ContainsAny(s, specialChars) {
		return s
	}
	var b bytes.Buffer
	b.WriteString("\"")
	for _, c := range s {
		if strings.ContainsAny(string(c), escapedChars) {
			b.WriteString("\\")
		}
		b.WriteRune(c)
	}
	b.WriteString("\"")
	return b.String()
}

type byteOrError struct {
	b   byte
	err error
}

// Shell manages a /bin/sh invocation with convenience functions to handle I/O.
// The shell is run in its own interactive TTY and should present its prompt.
type Shell struct {
	// cmd is a reference to the underlying sh process.
	cmd *exec.Cmd
	// cmdFinished is closed when cmd exits.
	cmdFinished chan struct{}

	// echo is whether the shell will echo input back to us.
	// This helps setting expectations of getting feedback of written bytes.
	echo bool
	// Control characters we expect to see in the shell.
	controlCharIntr string
	controlCharEOF  string

	// ptyMaster and ptyReplica are the TTY pair associated with the shell.
	ptyMaster  *os.File
	ptyReplica *os.File
	// readCh is a channel where everything read from ptyMaster is written.
	readCh chan byteOrError

	// logger is used for logging. It may be nil.
	logger Logger
}

// cleanup kills the shell process and closes the TTY.
// Users of this library get a reference to this function with NewShell.
func (s *Shell) cleanup() {
	s.logf("cleanup", "Shell cleanup started.")
	if s.cmd.ProcessState == nil {
		if err := s.cmd.Process.Kill(); err != nil {
			s.logf("cleanup", "cannot kill shell process: %v", err)
		}
		// We don't log the error returned by Wait because the monitorExit
		// goroutine will already do so.
		s.cmd.Wait()
	}
	s.ptyReplica.Close()
	s.ptyMaster.Close()
	// Wait for monitorExit goroutine to write exit status to the debug log.
	<-s.cmdFinished
	// Empty out everything in the readCh, but don't wait too long for it.
	var extraBytes bytes.Buffer
	unreadTimeout := time.After(100 * time.Millisecond)
unreadLoop:
	for {
		select {
		case r, ok := <-s.readCh:
			if !ok {
				break unreadLoop
			} else if r.err == nil {
				extraBytes.WriteByte(r.b)
			}
		case <-unreadTimeout:
			break unreadLoop
		}
	}
	if extraBytes.Len() > 0 {
		s.logIO("unread", extraBytes.Bytes(), nil)
	}
	s.logf("cleanup", "Shell cleanup complete.")
}

// logIO logs byte I/O to both standard logging and the test log, if provided.
func (s *Shell) logIO(prefix string, b []byte, err error) {
	var sb strings.Builder
	if len(b) > 0 {
		sb.WriteString(fmt.Sprintf("%q", b))
	} else {
		sb.WriteString("(nothing)")
	}
	if err != nil {
		sb.WriteString(fmt.Sprintf(" [error: %v]", err))
	}
	s.logf(prefix, "%s", sb.String())
}

// logf logs something to both standard logging and the test log, if provided.
func (s *Shell) logf(prefix, format string, values ...interface{}) {
	if s.logger != nil {
		s.logger.Logf("[%s] %s", prefix, fmt.Sprintf(format, values...))
	}
}

// monitorExit waits for the shell process to exit and logs the exit result.
func (s *Shell) monitorExit() {
	if err := s.cmd.Wait(); err != nil {
		s.logf("cmd", "shell process terminated: %v", err)
	} else {
		s.logf("cmd", "shell process terminated successfully")
	}
	close(s.cmdFinished)
}

// reader continuously reads the shell output and populates readCh.
func (s *Shell) reader(ctx context.Context) {
	b := make([]byte, 4096)
	defer close(s.readCh)
	for {
		select {
		case <-s.cmdFinished:
			// Shell process terminated; stop trying to read.
			return
		case <-ctx.Done():
			// Shell process will also have terminated in this case;
			// stop trying to read.
			// We don't print an error here because doing so would print this in the
			// normal case where the context passed to NewShell is canceled at the
			// end of a successful test.
			return
		default:
			// Shell still running, try reading.
		}
		if got, err := s.ptyMaster.Read(b); err != nil {
			s.readCh <- byteOrError{err: err}
			if err == io.EOF {
				return
			}
		} else {
			for i := 0; i < got; i++ {
				s.readCh <- byteOrError{b: b[i]}
			}
		}
	}
}

// readByte reads a single byte, respecting the context.
func (s *Shell) readByte(ctx context.Context) (byte, error) {
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case r := <-s.readCh:
		return r.b, r.err
	}
}

// readLoop reads as many bytes as possible until the context expires, b is
// full, or a short time passes. It returns how many bytes it has successfully
// read.
func (s *Shell) readLoop(ctx context.Context, b []byte) (int, error) {
	soonCtx, soonCancel := context.WithTimeout(ctx, 5*time.Second)
	defer soonCancel()
	var i int
	for i = 0; i < len(b) && soonCtx.Err() == nil; i++ {
		next, err := s.readByte(soonCtx)
		if err != nil {
			if i > 0 {
				s.logIO("read", b[:i-1], err)
			} else {
				s.logIO("read", nil, err)
			}
			return i, err
		}
		b[i] = next
	}
	s.logIO("read", b[:i], soonCtx.Err())
	return i, soonCtx.Err()
}

// readLine reads a single line. Strips out all \r characters for convenience.
// Upon error, it will still return what it has read so far.
// It will also exit quickly if the line content it has read so far (without a
// line break) matches `prompt`.
func (s *Shell) readLine(ctx context.Context, prompt string) ([]byte, error) {
	soonCtx, soonCancel := context.WithTimeout(ctx, 5*time.Second)
	defer soonCancel()
	var lineData bytes.Buffer
	var b byte
	var err error
	for soonCtx.Err() == nil && b != '\n' {
		b, err = s.readByte(soonCtx)
		if err != nil {
			data := lineData.Bytes()
			s.logIO("read", data, err)
			return data, err
		}
		if b != '\r' {
			lineData.WriteByte(b)
		}
		if bytes.Equal(lineData.Bytes(), []byte(prompt)) {
			// Assume that there will not be any further output if we get the prompt.
			// This avoids waiting for the read deadline just to read the prompt.
			break
		}
	}
	data := lineData.Bytes()
	s.logIO("read", data, soonCtx.Err())
	return data, soonCtx.Err()
}

// Expect verifies that the next `len(want)` bytes we read match `want`.
func (s *Shell) Expect(ctx context.Context, want []byte) error {
	errPrefix := fmt.Sprintf("want(%q)", want)
	b := make([]byte, len(want))
	got, err := s.readLoop(ctx, b)
	if err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("%s: context done (%w), got: %q", errPrefix, err, b[:got])
		}
		return fmt.Errorf("%s: %w", errPrefix, err)
	}
	if got < len(want) {
		return fmt.Errorf("%s: short read (read %d bytes, expected %d): %q", errPrefix, got, len(want), b[:got])
	}
	if !bytes.Equal(b, want) {
		return fmt.Errorf("got %q want %q", b, want)
	}
	return nil
}

// ExpectString verifies that the next `len(want)` bytes we read match `want`.
func (s *Shell) ExpectString(ctx context.Context, want string) error {
	return s.Expect(ctx, []byte(want))
}

// ExpectPrompt verifies that the next few bytes we read are the shell prompt.
func (s *Shell) ExpectPrompt(ctx context.Context) error {
	return s.ExpectString(ctx, Prompt)
}

// ExpectEmptyLine verifies that the next few bytes we read are an empty line,
// as defined by any number of carriage or line break characters.
func (s *Shell) ExpectEmptyLine(ctx context.Context) error {
	line, err := s.readLine(ctx, Prompt)
	if err != nil {
		return fmt.Errorf("cannot read line: %w", err)
	}
	if strings.Trim(string(line), "\r\n") != "" {
		return fmt.Errorf("line was not empty: %q", line)
	}
	return nil
}

// ExpectLine verifies that the next `len(want)` bytes we read match `want`,
// followed by carriage returns or newline characters.
func (s *Shell) ExpectLine(ctx context.Context, want string) error {
	if err := s.ExpectString(ctx, want); err != nil {
		return err
	}
	if err := s.ExpectEmptyLine(ctx); err != nil {
		return fmt.Errorf("ExpectLine(%q): no line break: %w", want, err)
	}
	return nil
}

// Write writes `b` to the shell and verifies that all of them get written.
func (s *Shell) Write(b []byte) error {
	written, err := s.ptyMaster.Write(b)
	s.logIO("write", b[:written], err)
	if err != nil {
		return fmt.Errorf("write(%q): %w", b, err)
	}
	if written != len(b) {
		return fmt.Errorf("write(%q): wrote %d of %d bytes (%q)", b, written, len(b), b[:written])
	}
	return nil
}

// WriteLine writes `line` (to which \n will be appended) to the shell.
// If the shell is in `echo` mode, it will also check that we got these bytes
// back to read.
func (s *Shell) WriteLine(ctx context.Context, line string) error {
	if err := s.Write([]byte(line + "\n")); err != nil {
		return err
	}
	if s.echo {
		// We expect to see everything we've typed.
		if err := s.ExpectLine(ctx, line); err != nil {
			return fmt.Errorf("echo: %w", err)
		}
	}
	return nil
}

// StartCommand is a convenience wrapper for WriteLine that mimics entering a
// command line and pressing Enter. It does some basic shell argument escaping.
func (s *Shell) StartCommand(ctx context.Context, cmd ...string) error {
	escaped := make([]string, len(cmd))
	for i, arg := range cmd {
		escaped[i] = shellEscape(arg)
	}
	return s.WriteLine(ctx, strings.Join(escaped, " "))
}

// GetCommandOutput gets all following bytes until the prompt is encountered.
// This is useful for matching the output of a command.
// All \r are removed for ease of matching.
func (s *Shell) GetCommandOutput(ctx context.Context) ([]byte, error) {
	return s.ReadUntil(ctx, Prompt)
}

// ReadUntil gets all following bytes until a certain line is encountered.
// This final line is not returned as part of the output, but everything before
// it (including the \n) is included.
// This is useful for matching the output of a command.
// All \r are removed for ease of matching.
func (s *Shell) ReadUntil(ctx context.Context, finalLine string) ([]byte, error) {
	var output bytes.Buffer
	for ctx.Err() == nil {
		line, err := s.readLine(ctx, finalLine)
		if err != nil {
			return nil, err
		}
		if bytes.Equal(line, []byte(finalLine)) {
			break
		}
		// readLine ensures that `line` either matches `finalLine` or contains \n.
		// Thus we can be confident that `line` has a \n here.
		output.Write(line)
	}
	return output.Bytes(), ctx.Err()
}

// RunCommand is a convenience wrapper for StartCommand + GetCommandOutput.
func (s *Shell) RunCommand(ctx context.Context, cmd ...string) ([]byte, error) {
	if err := s.StartCommand(ctx, cmd...); err != nil {
		return nil, err
	}
	return s.GetCommandOutput(ctx)
}

// RefreshSTTY interprets output from `stty -a` to check whether we are in echo
// mode and other settings.
// It will assume that any line matching `expectPrompt` means the end of
// the `stty -a` output.
// Why do this rather than using `tcgets`? Because this function can be used in
// conjunction with sub-shell processes that can allocate their own TTYs.
func (s *Shell) RefreshSTTY(ctx context.Context, expectPrompt string) error {
	// Temporarily assume we will not get any output.
	// If echo is actually on, we'll get the "stty -a" line as if it was command
	// output. This is OK because we parse the output generously.
	s.echo = false
	if err := s.WriteLine(ctx, "stty -a"); err != nil {
		return fmt.Errorf("could not run `stty -a`: %w", err)
	}
	sttyOutput, err := s.ReadUntil(ctx, expectPrompt)
	if err != nil {
		return fmt.Errorf("cannot get `stty -a` output: %w", err)
	}

	// Set default control characters in case we can't see them in the output.
	s.controlCharIntr = "^C"
	s.controlCharEOF = "^D"
	// stty output has two general notations:
	// `a = b;` (for control characters), and `option` vs `-option` (for boolean
	// options). We parse both kinds here.
	// For `a = b;`, `controlChar` contains `a`, and `previousToken` is used to
	// set `controlChar` to `previousToken` when we see an "=" token.
	var previousToken, controlChar string
	for _, token := range strings.Fields(string(sttyOutput)) {
		if controlChar != "" {
			value := strings.TrimSuffix(token, ";")
			switch controlChar {
			case "intr":
				s.controlCharIntr = value
			case "eof":
				s.controlCharEOF = value
			}
			controlChar = ""
		} else {
			switch token {
			case "=":
				controlChar = previousToken
			case "-echo":
				s.echo = false
			case "echo":
				s.echo = true
			}
		}
		previousToken = token
	}
	s.logf("stty", "refreshed settings: echo=%v, intr=%q, eof=%q", s.echo, s.controlCharIntr, s.controlCharEOF)
	return nil
}

// sendControlCode sends `code` to the shell and expects to see `repr`.
// If `expectLinebreak` is true, it also expects to see a linebreak.
func (s *Shell) sendControlCode(ctx context.Context, code byte, repr string, expectLinebreak bool) error {
	if err := s.Write([]byte{code}); err != nil {
		return fmt.Errorf("cannot send %q: %w", code, err)
	}
	if err := s.ExpectString(ctx, repr); err != nil {
		return fmt.Errorf("did not see %s: %w", repr, err)
	}
	if expectLinebreak {
		if err := s.ExpectEmptyLine(ctx); err != nil {
			return fmt.Errorf("linebreak after %s: %v", repr, err)
		}
	}
	return nil
}

// SendInterrupt sends the \x03 (Ctrl+C) control character to the shell.
func (s *Shell) SendInterrupt(ctx context.Context, expectLinebreak bool) error {
	return s.sendControlCode(ctx, 0x03, s.controlCharIntr, expectLinebreak)
}

// SendEOF sends the \x04 (Ctrl+D) control character to the shell.
func (s *Shell) SendEOF(ctx context.Context, expectLinebreak bool) error {
	return s.sendControlCode(ctx, 0x04, s.controlCharEOF, expectLinebreak)
}

// NewShell returns a new managed sh process along with a cleanup function.
// The caller is expected to call this function once it no longer needs the
// shell.
// The optional passed-in logger will be used for logging.
func NewShell(ctx context.Context, logger Logger) (*Shell, func(), error) {
	ptyMaster, ptyReplica, err := pty.Open()
	if err != nil {
		return nil, nil, fmt.Errorf("cannot create PTY: %w", err)
	}
	cmd := exec.CommandContext(ctx, "/bin/sh", "--noprofile", "--norc", "-i")
	cmd.Stdin = ptyReplica
	cmd.Stdout = ptyReplica
	cmd.Stderr = ptyReplica
	cmd.SysProcAttr = &unix.SysProcAttr{
		Setsid:  true,
		Setctty: true,
		Ctty:    0,
	}
	cmd.Env = append(cmd.Env, fmt.Sprintf("PS1=%s", Prompt))
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("cannot start shell: %w", err)
	}
	s := &Shell{
		cmd:         cmd,
		cmdFinished: make(chan struct{}),
		ptyMaster:   ptyMaster,
		ptyReplica:  ptyReplica,
		readCh:      make(chan byteOrError, 1<<20),
		logger:      logger,
	}
	s.logf("creation", "Shell spawned.")
	go s.monitorExit()
	go s.reader(ctx)
	setupCtx, setupCancel := context.WithTimeout(ctx, 5*time.Second)
	defer setupCancel()
	// We expect to see the prompt immediately on startup,
	// since the shell is started in interactive mode.
	if err := s.ExpectPrompt(setupCtx); err != nil {
		s.cleanup()
		return nil, nil, fmt.Errorf("did not get initial prompt: %w", err)
	}
	s.logf("creation", "Initial prompt observed.")
	// Get initial TTY settings.
	if err := s.RefreshSTTY(setupCtx, Prompt); err != nil {
		s.cleanup()
		return nil, nil, fmt.Errorf("cannot get initial STTY settings: %w", err)
	}
	return s, s.cleanup, nil
}
