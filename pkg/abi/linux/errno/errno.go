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

// Package errno holds errno codes for abi/linux.
package errno

// Errno represents a Linux errno value.
type Errno uint32

// Errno values from include/uapi/asm-generic/errno-base.h.
const (
	NOERRNO = iota
	EPERM
	ENOENT
	ESRCH
	EINTR
	EIO
	ENXIO
	E2BIG
	ENOEXEC
	EBADF
	ECHILD // 10
	EAGAIN
	ENOMEM
	EACCES
	EFAULT
	ENOTBLK
	EBUSY
	EEXIST
	EXDEV
	ENODEV
	ENOTDIR // 20
	EISDIR
	EINVAL
	ENFILE
	EMFILE
	ENOTTY
	ETXTBSY
	EFBIG
	ENOSPC
	ESPIPE
	EROFS // 30
	EMLINK
	EPIPE
	EDOM
	ERANGE
	// Errno values from include/uapi/asm-generic/errno.h.
	EDEADLK
	ENAMETOOLONG
	ENOLCK
	ENOSYS
	ENOTEMPTY
	ELOOP  // 40
	_      // Skip for EWOULDBLOCK = EAGAIN.
	ENOMSG //42
	EIDRM
	ECHRNG
	EL2NSYNC
	EL3HLT
	EL3RST
	ELNRNG
	EUNATCH
	ENOCSI
	EL2HLT // 50
	EBADE
	EBADR
	EXFULL
	ENOANO
	EBADRQC
	EBADSLT
	_ // Skip for EDEADLOCK = EDEADLK.
	EBFONT
	ENOSTR // 60
	ENODATA
	ETIME
	ENOSR
	_ // Skip for ENOENT = ENONET.
	ENOPKG
	EREMOTE
	ENOLINK
	EADV
	ESRMNT
	ECOMM // 70
	EPROTO
	EMULTIHOP
	EDOTDOT
	EBADMSG
	EOVERFLOW
	ENOTUNIQ
	EBADFD
	EREMCHG
	ELIBACC
	ELIBBAD // 80
	ELIBSCN
	ELIBMAX
	ELIBEXEC
	EILSEQ
	ERESTART
	ESTRPIPE
	EUSERS
	ENOTSOCK
	EDESTADDRREQ
	EMSGSIZE // 90
	EPROTOTYPE
	ENOPROTOOPT
	EPROTONOSUPPORT
	ESOCKTNOSUPPORT
	EOPNOTSUPP
	EPFNOSUPPORT
	EAFNOSUPPORT
	EADDRINUSE
	EADDRNOTAVAIL
	ENETDOWN // 100
	ENETUNREACH
	ENETRESET
	ECONNABORTED
	ECONNRESET
	ENOBUFS
	EISCONN
	ENOTCONN
	ESHUTDOWN
	ETOOMANYREFS
	ETIMEDOUT // 110
	ECONNREFUSED
	EHOSTDOWN
	EHOSTUNREACH
	EALREADY
	EINPROGRESS
	ESTALE
	EUCLEAN
	ENOTNAM
	ENAVAIL
	EISNAM // 120
	EREMOTEIO
	EDQUOT
	ENOMEDIUM
	EMEDIUMTYPE
	ECANCELED
	ENOKEY
	EKEYEXPIRED
	EKEYREVOKED
	EKEYREJECTED
	EOWNERDEAD // 130
	ENOTRECOVERABLE
	ERFKILL
	EHWPOISON
)

// errnos derived from other errnos
const (
	EWOULDBLOCK = EAGAIN
	EDEADLOCK   = EDEADLK
	ENONET      = ENOENT
)
