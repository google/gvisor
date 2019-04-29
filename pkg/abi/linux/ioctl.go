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

// ioctl(2) requests provided by asm-generic/ioctls.h
//
// These are ordered by request number (low byte).
const (
	TCGETS      = 0x00005401
	TCSETS      = 0x00005402
	TCSETSW     = 0x00005403
	TCSETSF     = 0x00005404
	TCSBRK      = 0x00005409
	TIOCEXCL    = 0x0000540c
	TIOCNXCL    = 0x0000540d
	TIOCSCTTY   = 0x0000540e
	TIOCGPGRP   = 0x0000540f
	TIOCSPGRP   = 0x00005410
	TIOCOUTQ    = 0x00005411
	TIOCSTI     = 0x00005412
	TIOCGWINSZ  = 0x00005413
	TIOCSWINSZ  = 0x00005414
	TIOCMGET    = 0x00005415
	TIOCMBIS    = 0x00005416
	TIOCMBIC    = 0x00005417
	TIOCMSET    = 0x00005418
	TIOCINQ     = 0x0000541b
	FIONREAD    = TIOCINQ
	FIONBIO     = 0x00005421
	TIOCSETD    = 0x00005423
	TIOCNOTTY   = 0x00005422
	TIOCGETD    = 0x00005424
	TCSBRKP     = 0x00005425
	TIOCSBRK    = 0x00005427
	TIOCCBRK    = 0x00005428
	TIOCGSID    = 0x00005429
	TIOCGPTN    = 0x80045430
	TIOCSPTLCK  = 0x40045431
	TIOCGDEV    = 0x80045432
	TIOCVHANGUP = 0x00005437
	TCFLSH      = 0x0000540b
	TIOCCONS    = 0x0000541d
	TIOCSSERIAL = 0x0000541f
	TIOCGEXCL   = 0x80045440
	TIOCGPTPEER = 0x80045441
	TIOCGICOUNT = 0x0000545d
	FIONCLEX    = 0x00005450
	FIOCLEX     = 0x00005451
	FIOASYNC    = 0x00005452
	FIOSETOWN   = 0x00008901
	SIOCSPGRP   = 0x00008902
	FIOGETOWN   = 0x00008903
	SIOCGPGRP   = 0x00008904
)

// ioctl(2) requests provided by uapi/linux/sockios.h
const (
	SIOCGIFMEM    = 0x891f
	SIOCGIFPFLAGS = 0x8935
	SIOCGMIIPHY   = 0x8947
	SIOCGMIIREG   = 0x8948
)

// ioctl(2) requests provided by uapi/linux/android/binder.h
const (
	BinderWriteReadIoctl       = 0xc0306201
	BinderSetIdleTimeoutIoctl  = 0x40086203
	BinderSetMaxThreadsIoctl   = 0x40046205
	BinderSetIdlePriorityIoctl = 0x40046206
	BinderSetContextMgrIoctl   = 0x40046207
	BinderThreadExitIoctl      = 0x40046208
	BinderVersionIoctl         = 0xc0046209
)

// ioctl(2) requests provided by drivers/staging/android/uapi/ashmem.h
const (
	AshmemSetNameIoctl        = 0x41007701
	AshmemGetNameIoctl        = 0x81007702
	AshmemSetSizeIoctl        = 0x40087703
	AshmemGetSizeIoctl        = 0x00007704
	AshmemSetProtMaskIoctl    = 0x40087705
	AshmemGetProtMaskIoctl    = 0x00007706
	AshmemPinIoctl            = 0x40087707
	AshmemUnpinIoctl          = 0x40087708
	AshmemGetPinStatusIoctl   = 0x00007709
	AshmemPurgeAllCachesIoctl = 0x0000770a
)
