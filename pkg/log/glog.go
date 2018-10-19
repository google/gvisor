// Copyright 2018 Google LLC
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

package log

import (
	"os"
	"time"
)

// GoogleEmitter is a wrapper that emits logs in a format compatible with
// package github.com/golang/glog.
type GoogleEmitter struct {
	// Emitter is the underlying emitter.
	Emitter
}

// buffer is a simple inline buffer to avoid churn. The data slice is generally
// kept to the local byte array, and we avoid having to allocate it on the heap.
type buffer struct {
	local [256]byte
	data  []byte
}

func (b *buffer) start() {
	b.data = b.local[:0]
}

func (b *buffer) String() string {
	return unsafeString(b.data)
}

func (b *buffer) write(c byte) {
	b.data = append(b.data, c)
}

func (b *buffer) writeAll(d []byte) {
	b.data = append(b.data, d...)
}

func (b *buffer) writeOneDigit(d byte) {
	b.write('0' + d)
}

func (b *buffer) writeTwoDigits(v int) {
	v = v % 100
	b.writeOneDigit(byte(v / 10))
	b.writeOneDigit(byte(v % 10))
}

func (b *buffer) writeSixDigits(v int) {
	v = v % 1000000
	b.writeOneDigit(byte(v / 100000))
	b.writeOneDigit(byte((v % 100000) / 10000))
	b.writeOneDigit(byte((v % 10000) / 1000))
	b.writeOneDigit(byte((v % 1000) / 100))
	b.writeOneDigit(byte((v % 100) / 10))
	b.writeOneDigit(byte(v % 10))
}

func calculateBytes(v int, pad int) []byte {
	var d []byte
	r := 1

	for n := 10; v >= r; n = n * 10 {
		d = append(d, '0'+byte((v%n)/r))
		r = n
	}

	for i := len(d); i < pad; i++ {
		d = append(d, ' ')
	}

	for i := 0; i < len(d)/2; i++ {
		d[i], d[len(d)-(i+1)] = d[len(d)-(i+1)], d[i]
	}
	return d
}

// pid is used for the threadid component of the header.
//
// The glog package logger uses 7 spaces of padding. See
// glob.loggingT.formatHeader.
var pid = calculateBytes(os.Getpid(), 7)

// caller is faked out as the caller. See FIXME below.
var caller = []byte("x:0")

// Emit emits the message, google-style.
func (g GoogleEmitter) Emit(level Level, timestamp time.Time, format string, args ...interface{}) {
	var b buffer
	b.start()

	// Log lines have this form:
	//   Lmmdd hh:mm:ss.uuuuuu threadid file:line] msg...
	//
	// where the fields are defined as follows:
	//   L                A single character, representing the log level (eg 'I' for INFO)
	//   mm               The month (zero padded; ie May is '05')
	//   dd               The day (zero padded)
	//   hh:mm:ss.uuuuuu  Time in hours, minutes and fractional seconds
	//   threadid         The space-padded thread ID as returned by GetTID()
	//   file             The file name
	//   line             The line number
	//   msg              The user-supplied message

	// Log level.
	switch level {
	case Debug:
		b.write('D')
	case Info:
		b.write('I')
	case Warning:
		b.write('W')
	}

	// Timestamp.
	_, month, day := timestamp.Date()
	hour, minute, second := timestamp.Clock()
	b.writeTwoDigits(int(month))
	b.writeTwoDigits(int(day))
	b.write(' ')
	b.writeTwoDigits(int(hour))
	b.write(':')
	b.writeTwoDigits(int(minute))
	b.write(':')
	b.writeTwoDigits(int(second))
	b.write('.')
	b.writeSixDigits(int(timestamp.Nanosecond() / 1000))
	b.write(' ')

	// The pid.
	b.writeAll(pid)
	b.write(' ')

	// FIXME: The caller, fabricated. This really sucks, but it
	// is unacceptable to put runtime.Callers() in the hot path.
	b.writeAll(caller)
	b.write(']')
	b.write(' ')

	// User-provided format string, copied.
	for i := 0; i < len(format); i++ {
		b.write(format[i])
	}

	// End with a newline.
	b.write('\n')

	// Pass to the underlying routine.
	g.Emitter.Emit(level, timestamp, b.String(), args...)
}
