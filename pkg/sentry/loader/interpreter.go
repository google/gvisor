// Copyright 2018 Google Inc.
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

package loader

import (
	"bytes"
	"io"

	"gvisor.googlesource.com/gvisor/pkg/sentry/context"
	"gvisor.googlesource.com/gvisor/pkg/sentry/fs"
	"gvisor.googlesource.com/gvisor/pkg/sentry/usermem"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

const (
	// interpreterScriptMagic identifies an interpreter script.
	interpreterScriptMagic = "#!"

	// interpMaxLineLength is the maximum length for the first line of an
	// interpreter script.
	//
	// From execve(2): "A maximum line length of 127 characters is allowed
	// for the first line in a #! executable shell script."
	interpMaxLineLength = 127
)

// parseInterpreterScript returns the interpreter path and argv.
func parseInterpreterScript(ctx context.Context, filename string, f *fs.File, argv, envv []string) (newpath string, newargv []string, err error) {
	line := make([]byte, interpMaxLineLength)
	n, err := readFull(ctx, f, usermem.BytesIOSequence(line), 0)
	// Short read is OK.
	if err != nil && err != io.ErrUnexpectedEOF {
		if err == io.EOF {
			err = syserror.ENOEXEC
		}
		return "", []string{}, err
	}
	line = line[:n]

	if !bytes.Equal(line[:2], []byte(interpreterScriptMagic)) {
		return "", []string{}, syserror.ENOEXEC
	}
	// Ignore #!.
	line = line[2:]

	// Ignore everything after newline.
	// Linux silently truncates the remainder of the line if it exceeds
	// interpMaxLineLength.
	i := bytes.IndexByte(line, '\n')
	if i > 0 {
		line = line[:i]
	}

	// Skip any whitespace before the interpeter.
	line = bytes.TrimLeft(line, " \t")

	// Linux only looks for a space or tab delimiting the interpreter and
	// arg.
	//
	// execve(2): "On Linux, the entire string following the interpreter
	// name is passed as a single argument to the interpreter, and this
	// string can include white space."
	interp := line
	var arg []byte
	i = bytes.IndexAny(line, " \t")
	if i >= 0 {
		interp = line[:i]
		if i+1 < len(line) {
			arg = line[i+1:]
		}
	}

	if string(interp) == "" {
		ctx.Infof("Interpreter script contains no interpreter: %v", line)
		return "", []string{}, syserror.ENOEXEC
	}

	// Build the new argument list:
	//
	// 1. The interpreter.
	newargv = append(newargv, string(interp))

	// 2. The optional interpreter argument.
	if len(arg) > 0 {
		newargv = append(newargv, string(arg))
	}

	// 3. The original arguments. The original argv[0] is replaced with the
	// full script filename.
	if len(argv) > 0 {
		argv[0] = filename
	} else {
		argv = []string{filename}
	}
	newargv = append(newargv, argv...)

	return string(interp), newargv, nil
}
