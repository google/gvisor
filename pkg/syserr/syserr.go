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

// Package syserr contains sandbox-internal errors. These errors are distinct
// from both the errors returned by host system calls and the errors returned
// to sandboxed applications.
package syserr

import (
	"fmt"
	"syscall"

	"gvisor.googlesource.com/gvisor/pkg/abi/linux"
	"gvisor.googlesource.com/gvisor/pkg/syserror"
)

// Error represents an internal error.
type Error struct {
	string
}

// New creates a new Error and adds a translation for it.
//
// New must only be called at init.
func New(message string, linuxTranslation *linux.Errno) *Error {
	err := &Error{message}
	linuxABITranslations[err] = linuxTranslation

	// TODO: Remove this.
	if linuxTranslation == nil {
		linuxBackwardsTranslations[err] = nil
	} else {
		e := error(syscall.Errno(linuxTranslation.Number()))
		// syserror.ErrWouldBlock gets translated to syserror.EWOULDBLOCK and
		// enables proper blocking semantics. This should temporary address the
		// class of blocking bugs that keep popping up with the current state of
		// the error space.
		if e == syserror.EWOULDBLOCK {
			e = syserror.ErrWouldBlock
		}
		linuxBackwardsTranslations[err] = e
	}

	return err
}

// NewWithoutTranslation creates a new Error. If translation is attempted on
// the error, translation will fail.
func NewWithoutTranslation(message string) *Error {
	return &Error{message}
}

// String implements fmt.Stringer.String.
func (e *Error) String() string {
	if e == nil {
		return "<nil>"
	}
	return e.string
}

// TODO: Remove this.
var linuxBackwardsTranslations = map[*Error]error{}

// ToError translates an Error to a corresponding error value.
//
// TODO: Remove this.
func (e *Error) ToError() error {
	if e == nil {
		return nil
	}
	err, ok := linuxBackwardsTranslations[e]
	if !ok {
		panic(fmt.Sprintf("unknown error: %q", e.string))
	}
	return err
}

// TODO: Remove or replace most of these errors.
//
// Some of the errors should be replaced with package specific errors and
// others should be removed entirely.
var (
	ErrNotPermitted               = New("operation not permitted", linux.EPERM)
	ErrNoFileOrDir                = New("no such file or directory", linux.ENOENT)
	ErrNoProcess                  = New("no such process", linux.ESRCH)
	ErrInterrupted                = New("interrupted system call", linux.EINTR)
	ErrIO                         = New("I/O error", linux.EIO)
	ErrDeviceOrAddress            = New("no such device or address", linux.ENXIO)
	ErrTooManyArgs                = New("argument list too long", linux.E2BIG)
	ErrEcec                       = New("exec format error", linux.ENOEXEC)
	ErrBadFD                      = New("bad file number", linux.EBADF)
	ErrNoChild                    = New("no child processes", linux.ECHILD)
	ErrTryAgain                   = New("try again", linux.EAGAIN)
	ErrNoMemory                   = New("out of memory", linux.ENOMEM)
	ErrPermissionDenied           = New("permission denied", linux.EACCES)
	ErrBadAddress                 = New("bad address", linux.EFAULT)
	ErrNotBlockDevice             = New("block device required", linux.ENOTBLK)
	ErrBusy                       = New("device or resource busy", linux.EBUSY)
	ErrExists                     = New("file exists", linux.EEXIST)
	ErrCrossDeviceLink            = New("cross-device link", linux.EXDEV)
	ErrNoDevice                   = New("no such device", linux.ENODEV)
	ErrNotDir                     = New("not a directory", linux.ENOTDIR)
	ErrIsDir                      = New("is a directory", linux.EISDIR)
	ErrInvalidArgument            = New("invalid argument", linux.EINVAL)
	ErrFileTableOverflow          = New("file table overflow", linux.ENFILE)
	ErrTooManyOpenFiles           = New("too many open files", linux.EMFILE)
	ErrNotTTY                     = New("not a typewriter", linux.ENOTTY)
	ErrTestFileBusy               = New("text file busy", linux.ETXTBSY)
	ErrFileTooBig                 = New("file too large", linux.EFBIG)
	ErrNoSpace                    = New("no space left on device", linux.ENOSPC)
	ErrIllegalSeek                = New("illegal seek", linux.ESPIPE)
	ErrReadOnlyFS                 = New("read-only file system", linux.EROFS)
	ErrTooManyLinks               = New("too many links", linux.EMLINK)
	ErrBrokenPipe                 = New("broken pipe", linux.EPIPE)
	ErrDomain                     = New("math argument out of domain of func", linux.EDOM)
	ErrRange                      = New("math result not representable", linux.ERANGE)
	ErrDeadlock                   = New("resource deadlock would occur", linux.EDEADLOCK)
	ErrNameTooLong                = New("file name too long", linux.ENAMETOOLONG)
	ErrNoLocksAvailable           = New("no record locks available", linux.ENOLCK)
	ErrInvalidSyscall             = New("invalid system call number", linux.ENOSYS)
	ErrDirNotEmpty                = New("directory not empty", linux.ENOTEMPTY)
	ErrLinkLoop                   = New("too many symbolic links encountered", linux.ELOOP)
	ErrWouldBlock                 = New("operation would block", linux.EWOULDBLOCK)
	ErrNoMessage                  = New("no message of desired type", linux.ENOMSG)
	ErrIdentifierRemoved          = New("identifier removed", linux.EIDRM)
	ErrChannelOutOfRange          = New("channel number out of range", linux.ECHRNG)
	ErrLevelTwoNotSynced          = New("level 2 not synchronized", linux.EL2NSYNC)
	ErrLevelThreeHalted           = New("level 3 halted", linux.EL3HLT)
	ErrLevelThreeReset            = New("level 3 reset", linux.EL3RST)
	ErrLinkNumberOutOfRange       = New("link number out of range", linux.ELNRNG)
	ErrProtocolDriverNotAttached  = New("protocol driver not attached", linux.EUNATCH)
	ErrNoCSIAvailable             = New("no CSI structure available", linux.ENOCSI)
	ErrLevelTwoHalted             = New("level 2 halted", linux.EL2HLT)
	ErrInvalidExchange            = New("invalid exchange", linux.EBADE)
	ErrInvalidRequestDescriptor   = New("invalid request descriptor", linux.EBADR)
	ErrExchangeFull               = New("exchange full", linux.EXFULL)
	ErrNoAnode                    = New("no anode", linux.ENOANO)
	ErrInvalidRequestCode         = New("invalid request code", linux.EBADRQC)
	ErrInvalidSlot                = New("invalid slot", linux.EBADSLT)
	ErrBadFontFile                = New("bad font file format", linux.EBFONT)
	ErrNotStream                  = New("device not a stream", linux.ENOSTR)
	ErrNoDataAvailable            = New("no data available", linux.ENODATA)
	ErrTimerExpired               = New("timer expired", linux.ETIME)
	ErrStreamsResourceDepleted    = New("out of streams resources", linux.ENOSR)
	ErrMachineNotOnNetwork        = New("machine is not on the network", linux.ENONET)
	ErrPackageNotInstalled        = New("package not installed", linux.ENOPKG)
	ErrIsRemote                   = New("object is remote", linux.EREMOTE)
	ErrNoLink                     = New("link has been severed", linux.ENOLINK)
	ErrAdvertise                  = New("advertise error", linux.EADV)
	ErrSRMount                    = New("srmount error", linux.ESRMNT)
	ErrSendCommunication          = New("communication error on send", linux.ECOMM)
	ErrProtocol                   = New("protocol error", linux.EPROTO)
	ErrMultihopAttempted          = New("multihop attempted", linux.EMULTIHOP)
	ErrRFS                        = New("RFS specific error", linux.EDOTDOT)
	ErrInvalidDataMessage         = New("not a data message", linux.EBADMSG)
	ErrOverflow                   = New("value too large for defined data type", linux.EOVERFLOW)
	ErrNetworkNameNotUnique       = New("name not unique on network", linux.ENOTUNIQ)
	ErrFDInBadState               = New("file descriptor in bad state", linux.EBADFD)
	ErrRemoteAddressChanged       = New("remote address changed", linux.EREMCHG)
	ErrSharedLibraryInaccessible  = New("can not access a needed shared library", linux.ELIBACC)
	ErrCorruptedSharedLibrary     = New("accessing a corrupted shared library", linux.ELIBBAD)
	ErrLibSectionCorrupted        = New(".lib section in a.out corrupted", linux.ELIBSCN)
	ErrTooManySharedLibraries     = New("attempting to link in too many shared libraries", linux.ELIBMAX)
	ErrSharedLibraryExeced        = New("cannot exec a shared library directly", linux.ELIBEXEC)
	ErrIllegalByteSequence        = New("illegal byte sequence", linux.EILSEQ)
	ErrShouldRestart              = New("interrupted system call should be restarted", linux.ERESTART)
	ErrStreamPipe                 = New("streams pipe error", linux.ESTRPIPE)
	ErrTooManyUsers               = New("too many users", linux.EUSERS)
	ErrNotASocket                 = New("socket operation on non-socket", linux.ENOTSOCK)
	ErrDestinationAddressRequired = New("destination address required", linux.EDESTADDRREQ)
	ErrMessageTooLong             = New("message too long", linux.EMSGSIZE)
	ErrWrongProtocolForSocket     = New("protocol wrong type for socket", linux.EPROTOTYPE)
	ErrProtocolNotAvailable       = New("protocol not available", linux.ENOPROTOOPT)
	ErrProtocolNotSupported       = New("protocol not supported", linux.EPROTONOSUPPORT)
	ErrSocketNotSupported         = New("socket type not supported", linux.ESOCKTNOSUPPORT)
	ErrEndpointOperation          = New("operation not supported on transport endpoint", linux.EOPNOTSUPP)
	ErrProtocolFamilyNotSupported = New("protocol family not supported", linux.EPFNOSUPPORT)
	ErrAddressFamilyNotSupported  = New("address family not supported by protocol", linux.EAFNOSUPPORT)
	ErrAddressInUse               = New("address already in use", linux.EADDRINUSE)
	ErrAddressNotAvailable        = New("cannot assign requested address", linux.EADDRNOTAVAIL)
	ErrNetworkDown                = New("network is down", linux.ENETDOWN)
	ErrNetworkUnreachable         = New("network is unreachable", linux.ENETUNREACH)
	ErrNetworkReset               = New("network dropped connection because of reset", linux.ENETRESET)
	ErrConnectionAborted          = New("software caused connection abort", linux.ECONNABORTED)
	ErrConnectionReset            = New("connection reset by peer", linux.ECONNRESET)
	ErrNoBufferSpace              = New("no buffer space available", linux.ENOBUFS)
	ErrAlreadyConnected           = New("transport endpoint is already connected", linux.EISCONN)
	ErrNotConnected               = New("transport endpoint is not connected", linux.ENOTCONN)
	ErrShutdown                   = New("cannot send after transport endpoint shutdown", linux.ESHUTDOWN)
	ErrTooManyRefs                = New("too many references: cannot splice", linux.ETOOMANYREFS)
	ErrTimedOut                   = New("connection timed out", linux.ETIMEDOUT)
	ErrConnectionRefused          = New("connection refused", linux.ECONNREFUSED)
	ErrHostDown                   = New("host is down", linux.EHOSTDOWN)
	ErrNoRoute                    = New("no route to host", linux.EHOSTUNREACH)
	ErrAlreadyInProgress          = New("operation already in progress", linux.EALREADY)
	ErrInProgress                 = New("operation now in progress", linux.EINPROGRESS)
	ErrStaleFileHandle            = New("stale file handle", linux.ESTALE)
	ErrStructureNeedsCleaning     = New("structure needs cleaning", linux.EUCLEAN)
	ErrIsNamedFile                = New("is a named type file", linux.ENOTNAM)
	ErrRemoteIO                   = New("remote I/O error", linux.EREMOTEIO)
	ErrQuotaExceeded              = New("quota exceeded", linux.EDQUOT)
	ErrNoMedium                   = New("no medium found", linux.ENOMEDIUM)
	ErrWrongMediumType            = New("wrong medium type", linux.EMEDIUMTYPE)
	ErrCanceled                   = New("operation Canceled", linux.ECANCELED)
	ErrNoKey                      = New("required key not available", linux.ENOKEY)
	ErrKeyExpired                 = New("key has expired", linux.EKEYEXPIRED)
	ErrKeyRevoked                 = New("key has been revoked", linux.EKEYREVOKED)
	ErrKeyRejected                = New("key was rejected by service", linux.EKEYREJECTED)
	ErrOwnerDied                  = New("owner died", linux.EOWNERDEAD)
	ErrNotRecoverable             = New("state not recoverable", linux.ENOTRECOVERABLE)
)

// FromError converts a generic error to an *Error.
//
// TODO: Remove this function.
func FromError(err error) *Error {
	if err == nil {
		return nil
	}
	if errno, ok := err.(syscall.Errno); ok {
		return FromHost(errno)
	}
	if errno, ok := syserror.TranslateError(err); ok {
		return FromHost(errno)
	}
	panic("unknown error: " + err.Error())
}
