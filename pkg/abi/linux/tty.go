// Copyright 2018 The gVisor Authors.
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

package linux

const (
	// NumControlCharacters is the number of control characters in Termios.
	NumControlCharacters = 19
	// disabledChar is used to indicate that a control character is
	// disabled.
	disabledChar = 0
)

// Winsize is struct winsize, defined in uapi/asm-generic/termios.h.
type Winsize struct {
	Row    uint16
	Col    uint16
	Xpixel uint16
	Ypixel uint16
}

// Termios is struct termios, defined in uapi/asm-generic/termbits.h.
type Termios struct {
	InputFlags        uint32
	OutputFlags       uint32
	ControlFlags      uint32
	LocalFlags        uint32
	LineDiscipline    uint8
	ControlCharacters [NumControlCharacters]uint8
}

// KernelTermios is struct ktermios/struct termios2, defined in
// uapi/asm-generic/termbits.h.
//
// +stateify savable
type KernelTermios struct {
	InputFlags        uint32
	OutputFlags       uint32
	ControlFlags      uint32
	LocalFlags        uint32
	LineDiscipline    uint8
	ControlCharacters [NumControlCharacters]uint8
	InputSpeed        uint32
	OutputSpeed       uint32
}

// IEnabled returns whether flag is enabled in termios input flags.
func (t *KernelTermios) IEnabled(flag uint32) bool {
	return t.InputFlags&flag == flag
}

// OEnabled returns whether flag is enabled in termios output flags.
func (t *KernelTermios) OEnabled(flag uint32) bool {
	return t.OutputFlags&flag == flag
}

// CEnabled returns whether flag is enabled in termios control flags.
func (t *KernelTermios) CEnabled(flag uint32) bool {
	return t.ControlFlags&flag == flag
}

// LEnabled returns whether flag is enabled in termios local flags.
func (t *KernelTermios) LEnabled(flag uint32) bool {
	return t.LocalFlags&flag == flag
}

// ToTermios copies fields that are shared with Termios into a new Termios
// struct.
func (t *KernelTermios) ToTermios() Termios {
	return Termios{
		InputFlags:        t.InputFlags,
		OutputFlags:       t.OutputFlags,
		ControlFlags:      t.ControlFlags,
		LocalFlags:        t.LocalFlags,
		LineDiscipline:    t.LineDiscipline,
		ControlCharacters: t.ControlCharacters,
	}
}

// FromTermios copies fields that are shared with Termios into this
// KernelTermios struct.
func (t *KernelTermios) FromTermios(term Termios) {
	t.InputFlags = term.InputFlags
	t.OutputFlags = term.OutputFlags
	t.ControlFlags = term.ControlFlags
	t.LocalFlags = term.LocalFlags
	t.LineDiscipline = term.LineDiscipline
	t.ControlCharacters = term.ControlCharacters
}

// IsTerminating returns whether c is a line terminating character.
func (t *KernelTermios) IsTerminating(cBytes []byte) bool {
	// All terminating characters are 1 byte.
	if len(cBytes) != 1 {
		return false
	}
	c := cBytes[0]

	// Is this the user-set EOF character?
	if t.IsEOF(c) {
		return true
	}

	switch c {
	case disabledChar:
		return false
	case '\n', t.ControlCharacters[VEOL]:
		return true
	case t.ControlCharacters[VEOL2]:
		return t.LEnabled(IEXTEN)
	}
	return false
}

// IsEOF returns whether c is the EOF character.
func (t *KernelTermios) IsEOF(c byte) bool {
	return c == t.ControlCharacters[VEOF] && t.ControlCharacters[VEOF] != disabledChar
}

// Input flags.
const (
	IGNBRK  = 0000001
	BRKINT  = 0000002
	IGNPAR  = 0000004
	PARMRK  = 0000010
	INPCK   = 0000020
	ISTRIP  = 0000040
	INLCR   = 0000100
	IGNCR   = 0000200
	ICRNL   = 0000400
	IUCLC   = 0001000
	IXON    = 0002000
	IXANY   = 0004000
	IXOFF   = 0010000
	IMAXBEL = 0020000
	IUTF8   = 0040000
)

// Output flags.
const (
	OPOST  = 0000001
	OLCUC  = 0000002
	ONLCR  = 0000004
	OCRNL  = 0000010
	ONOCR  = 0000020
	ONLRET = 0000040
	OFILL  = 0000100
	OFDEL  = 0000200
	NLDLY  = 0000400
	NL0    = 0000000
	NL1    = 0000400
	CRDLY  = 0003000
	CR0    = 0000000
	CR1    = 0001000
	CR2    = 0002000
	CR3    = 0003000
	TABDLY = 0014000
	TAB0   = 0000000
	TAB1   = 0004000
	TAB2   = 0010000
	TAB3   = 0014000
	XTABS  = 0014000
	BSDLY  = 0020000
	BS0    = 0000000
	BS1    = 0020000
	VTDLY  = 0040000
	VT0    = 0000000
	VT1    = 0040000
	FFDLY  = 0100000
	FF0    = 0000000
	FF1    = 0100000
)

// Control flags.
const (
	CBAUD    = 0010017
	B0       = 0000000
	B50      = 0000001
	B75      = 0000002
	B110     = 0000003
	B134     = 0000004
	B150     = 0000005
	B200     = 0000006
	B300     = 0000007
	B600     = 0000010
	B1200    = 0000011
	B1800    = 0000012
	B2400    = 0000013
	B4800    = 0000014
	B9600    = 0000015
	B19200   = 0000016
	B38400   = 0000017
	EXTA     = B19200
	EXTB     = B38400
	CSIZE    = 0000060
	CS5      = 0000000
	CS6      = 0000020
	CS7      = 0000040
	CS8      = 0000060
	CSTOPB   = 0000100
	CREAD    = 0000200
	PARENB   = 0000400
	PARODD   = 0001000
	HUPCL    = 0002000
	CLOCAL   = 0004000
	CBAUDEX  = 0010000
	BOTHER   = 0010000
	B57600   = 0010001
	B115200  = 0010002
	B230400  = 0010003
	B460800  = 0010004
	B500000  = 0010005
	B576000  = 0010006
	B921600  = 0010007
	B1000000 = 0010010
	B1152000 = 0010011
	B1500000 = 0010012
	B2000000 = 0010013
	B2500000 = 0010014
	B3000000 = 0010015
	B3500000 = 0010016
	B4000000 = 0010017
	CIBAUD   = 002003600000
	CMSPAR   = 010000000000
	CRTSCTS  = 020000000000

	// IBSHIFT is the shift from CBAUD to CIBAUD.
	IBSHIFT = 16
)

// Local flags.
const (
	ISIG    = 0000001
	ICANON  = 0000002
	XCASE   = 0000004
	ECHO    = 0000010
	ECHOE   = 0000020
	ECHOK   = 0000040
	ECHONL  = 0000100
	NOFLSH  = 0000200
	TOSTOP  = 0000400
	ECHOCTL = 0001000
	ECHOPRT = 0002000
	ECHOKE  = 0004000
	FLUSHO  = 0010000
	PENDIN  = 0040000
	IEXTEN  = 0100000
	EXTPROC = 0200000
)

// Control Character indices.
const (
	VINTR    = 0
	VQUIT    = 1
	VERASE   = 2
	VKILL    = 3
	VEOF     = 4
	VTIME    = 5
	VMIN     = 6
	VSWTC    = 7
	VSTART   = 8
	VSTOP    = 9
	VSUSP    = 10
	VEOL     = 11
	VREPRINT = 12
	VDISCARD = 13
	VWERASE  = 14
	VLNEXT   = 15
	VEOL2    = 16
)

// ControlCharacter returns the termios-style control character for the passed
// character.
//
// e.g., for Ctrl-C, i.e., ^C, call ControlCharacter('C').
//
// Standard control characters are ASCII bytes 0 through 31.
func ControlCharacter(c byte) uint8 {
	// A is 1, B is 2, etc.
	return uint8(c - 'A' + 1)
}

// DefaultControlCharacters is the default set of Termios control characters.
var DefaultControlCharacters = [NumControlCharacters]uint8{
	ControlCharacter('C'),  // VINTR = ^C
	ControlCharacter('\\'), // VQUIT = ^\
	'\x7f',                 // VERASE = DEL
	ControlCharacter('U'),  // VKILL = ^U
	ControlCharacter('D'),  // VEOF = ^D
	0,                      // VTIME
	1,                      // VMIN
	0,                      // VSWTC
	ControlCharacter('Q'),  // VSTART = ^Q
	ControlCharacter('S'),  // VSTOP = ^S
	ControlCharacter('Z'),  // VSUSP = ^Z
	0,                      // VEOL
	ControlCharacter('R'),  // VREPRINT = ^R
	ControlCharacter('O'),  // VDISCARD = ^O
	ControlCharacter('W'),  // VWERASE = ^W
	ControlCharacter('V'),  // VLNEXT = ^V
	0,                      // VEOL2
}

// MasterTermios is the terminal configuration of the master end of a Unix98
// pseudoterminal.
var MasterTermios = KernelTermios{
	ControlFlags:      B38400 | CS8 | CREAD,
	ControlCharacters: DefaultControlCharacters,
	InputSpeed:        38400,
	OutputSpeed:       38400,
}

// DefaultSlaveTermios is the default terminal configuration of the slave end
// of a Unix98 pseudoterminal.
var DefaultSlaveTermios = KernelTermios{
	InputFlags:        ICRNL | IXON,
	OutputFlags:       OPOST | ONLCR,
	ControlFlags:      B38400 | CS8 | CREAD,
	LocalFlags:        ISIG | ICANON | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE | IEXTEN,
	ControlCharacters: DefaultControlCharacters,
	InputSpeed:        38400,
	OutputSpeed:       38400,
}

// WindowSize corresponds to struct winsize defined in
// include/uapi/asm-generic/termios.h.
//
// +stateify savable
type WindowSize struct {
	Rows uint16
	Cols uint16
	_    [4]byte // Padding for 2 unused shorts.
}
