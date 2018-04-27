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

// +build linux

package syserr

import (
	"syscall"
)

var linuxHostTranslations = map[syscall.Errno]*Error{
	syscall.EPERM:           ErrNotPermitted,
	syscall.ENOENT:          ErrNoFileOrDir,
	syscall.ESRCH:           ErrNoProcess,
	syscall.EINTR:           ErrInterrupted,
	syscall.EIO:             ErrIO,
	syscall.ENXIO:           ErrDeviceOrAddress,
	syscall.E2BIG:           ErrTooManyArgs,
	syscall.ENOEXEC:         ErrEcec,
	syscall.EBADF:           ErrBadFD,
	syscall.ECHILD:          ErrNoChild,
	syscall.EAGAIN:          ErrTryAgain,
	syscall.ENOMEM:          ErrNoMemory,
	syscall.EACCES:          ErrPermissionDenied,
	syscall.EFAULT:          ErrBadAddress,
	syscall.ENOTBLK:         ErrNotBlockDevice,
	syscall.EBUSY:           ErrBusy,
	syscall.EEXIST:          ErrExists,
	syscall.EXDEV:           ErrCrossDeviceLink,
	syscall.ENODEV:          ErrNoDevice,
	syscall.ENOTDIR:         ErrNotDir,
	syscall.EISDIR:          ErrIsDir,
	syscall.EINVAL:          ErrInvalidArgument,
	syscall.ENFILE:          ErrFileTableOverflow,
	syscall.EMFILE:          ErrTooManyOpenFiles,
	syscall.ENOTTY:          ErrNotTTY,
	syscall.ETXTBSY:         ErrTestFileBusy,
	syscall.EFBIG:           ErrFileTooBig,
	syscall.ENOSPC:          ErrNoSpace,
	syscall.ESPIPE:          ErrIllegalSeek,
	syscall.EROFS:           ErrReadOnlyFS,
	syscall.EMLINK:          ErrTooManyLinks,
	syscall.EPIPE:           ErrBrokenPipe,
	syscall.EDOM:            ErrDomain,
	syscall.ERANGE:          ErrRange,
	syscall.EDEADLOCK:       ErrDeadlock,
	syscall.ENAMETOOLONG:    ErrNameTooLong,
	syscall.ENOLCK:          ErrNoLocksAvailable,
	syscall.ENOSYS:          ErrInvalidSyscall,
	syscall.ENOTEMPTY:       ErrDirNotEmpty,
	syscall.ELOOP:           ErrLinkLoop,
	syscall.ENOMSG:          ErrNoMessage,
	syscall.EIDRM:           ErrIdentifierRemoved,
	syscall.ECHRNG:          ErrChannelOutOfRange,
	syscall.EL2NSYNC:        ErrLevelTwoNotSynced,
	syscall.EL3HLT:          ErrLevelThreeHalted,
	syscall.EL3RST:          ErrLevelThreeReset,
	syscall.ELNRNG:          ErrLinkNumberOutOfRange,
	syscall.EUNATCH:         ErrProtocolDriverNotAttached,
	syscall.ENOCSI:          ErrNoCSIAvailable,
	syscall.EL2HLT:          ErrLevelTwoHalted,
	syscall.EBADE:           ErrInvalidExchange,
	syscall.EBADR:           ErrInvalidRequestDescriptor,
	syscall.EXFULL:          ErrExchangeFull,
	syscall.ENOANO:          ErrNoAnode,
	syscall.EBADRQC:         ErrInvalidRequestCode,
	syscall.EBADSLT:         ErrInvalidSlot,
	syscall.EBFONT:          ErrBadFontFile,
	syscall.ENOSTR:          ErrNotStream,
	syscall.ENODATA:         ErrNoDataAvailable,
	syscall.ETIME:           ErrTimerExpired,
	syscall.ENOSR:           ErrStreamsResourceDepleted,
	syscall.ENONET:          ErrMachineNotOnNetwork,
	syscall.ENOPKG:          ErrPackageNotInstalled,
	syscall.EREMOTE:         ErrIsRemote,
	syscall.ENOLINK:         ErrNoLink,
	syscall.EADV:            ErrAdvertise,
	syscall.ESRMNT:          ErrSRMount,
	syscall.ECOMM:           ErrSendCommunication,
	syscall.EPROTO:          ErrProtocol,
	syscall.EMULTIHOP:       ErrMultihopAttempted,
	syscall.EDOTDOT:         ErrRFS,
	syscall.EBADMSG:         ErrInvalidDataMessage,
	syscall.EOVERFLOW:       ErrOverflow,
	syscall.ENOTUNIQ:        ErrNetworkNameNotUnique,
	syscall.EBADFD:          ErrFDInBadState,
	syscall.EREMCHG:         ErrRemoteAddressChanged,
	syscall.ELIBACC:         ErrSharedLibraryInaccessible,
	syscall.ELIBBAD:         ErrCorruptedSharedLibrary,
	syscall.ELIBSCN:         ErrLibSectionCorrupted,
	syscall.ELIBMAX:         ErrTooManySharedLibraries,
	syscall.ELIBEXEC:        ErrSharedLibraryExeced,
	syscall.EILSEQ:          ErrIllegalByteSequence,
	syscall.ERESTART:        ErrShouldRestart,
	syscall.ESTRPIPE:        ErrStreamPipe,
	syscall.EUSERS:          ErrTooManyUsers,
	syscall.ENOTSOCK:        ErrNotASocket,
	syscall.EDESTADDRREQ:    ErrDestinationAddressRequired,
	syscall.EMSGSIZE:        ErrMessageTooLong,
	syscall.EPROTOTYPE:      ErrWrongProtocolForSocket,
	syscall.ENOPROTOOPT:     ErrProtocolNotAvailable,
	syscall.EPROTONOSUPPORT: ErrProtocolNotSupported,
	syscall.ESOCKTNOSUPPORT: ErrSocketNotSupported,
	syscall.EOPNOTSUPP:      ErrEndpointOperation,
	syscall.EPFNOSUPPORT:    ErrProtocolFamilyNotSupported,
	syscall.EAFNOSUPPORT:    ErrAddressFamilyNotSupported,
	syscall.EADDRINUSE:      ErrAddressInUse,
	syscall.EADDRNOTAVAIL:   ErrAddressNotAvailable,
	syscall.ENETDOWN:        ErrNetworkDown,
	syscall.ENETUNREACH:     ErrNetworkUnreachable,
	syscall.ENETRESET:       ErrNetworkReset,
	syscall.ECONNABORTED:    ErrConnectionAborted,
	syscall.ECONNRESET:      ErrConnectionReset,
	syscall.ENOBUFS:         ErrNoBufferSpace,
	syscall.EISCONN:         ErrAlreadyConnected,
	syscall.ENOTCONN:        ErrNotConnected,
	syscall.ESHUTDOWN:       ErrShutdown,
	syscall.ETOOMANYREFS:    ErrTooManyRefs,
	syscall.ETIMEDOUT:       ErrTimedOut,
	syscall.ECONNREFUSED:    ErrConnectionRefused,
	syscall.EHOSTDOWN:       ErrHostDown,
	syscall.EHOSTUNREACH:    ErrNoRoute,
	syscall.EALREADY:        ErrAlreadyInProgress,
	syscall.EINPROGRESS:     ErrInProgress,
	syscall.ESTALE:          ErrStaleFileHandle,
	syscall.EUCLEAN:         ErrStructureNeedsCleaning,
	syscall.ENOTNAM:         ErrIsNamedFile,
	syscall.EREMOTEIO:       ErrRemoteIO,
	syscall.EDQUOT:          ErrQuotaExceeded,
	syscall.ENOMEDIUM:       ErrNoMedium,
	syscall.EMEDIUMTYPE:     ErrWrongMediumType,
	syscall.ECANCELED:       ErrCanceled,
	syscall.ENOKEY:          ErrNoKey,
	syscall.EKEYEXPIRED:     ErrKeyExpired,
	syscall.EKEYREVOKED:     ErrKeyRevoked,
	syscall.EKEYREJECTED:    ErrKeyRejected,
	syscall.EOWNERDEAD:      ErrOwnerDied,
	syscall.ENOTRECOVERABLE: ErrNotRecoverable,
}

// FromHost translates a syscall.Errno to a corresponding Error value.
func FromHost(err syscall.Errno) *Error {
	e, ok := linuxHostTranslations[err]
	if !ok {
		panic("Unknown host errno " + err.Error())
	}
	return e
}
