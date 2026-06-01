/*
 * Linker script for the LoongArch64 VDSO. See vdso_arm64.lds for the
 * design rationale (position-independent, prelinked, mapped directly by
 * the sentry without dynamic-linker relocations).
 *
 * Notable LoongArch-specific bits:
 *   - OUTPUT_FORMAT / OUTPUT_ARCH use "elf64-loongarch" / loongarch64
 *     (matching binutils ≥ 2.40 for LoongArch).
 *   - The .text fill word is 0x03400000, the encoding of LoongArch's
 *     canonical NOP `andi $r0, $r0, 0` (Vol1 §2.2.1.7).
 *   - The exported symbol set follows the kernel's mainline LoongArch
 *     VDSO (see arch/loongarch/vdso/vdso.lds.S), which advertises the
 *     LINUX_5.10 ABI tag.
 */

VDSO_PRELINK = 0xffffffffff700000;

OUTPUT_FORMAT("elf64-loongarch", "elf64-loongarch", "elf64-loongarch")
OUTPUT_ARCH(loongarch64)

SECTIONS {
  /* The parameter page is mapped just before the VDSO. */
  _params = VDSO_PRELINK - 0x1000;

  . = VDSO_PRELINK + SIZEOF_HEADERS;

  .hash          : { *(.hash) }             :text
  .gnu.hash      : { *(.gnu.hash) }
  .dynsym        : { *(.dynsym) }
  .dynstr        : { *(.dynstr) }
  .gnu.version   : { *(.gnu.version) }
  .gnu.version_d : { *(.gnu.version_d) }
  .gnu.version_r : { *(.gnu.version_r) }

  .eh_frame_hdr  : { *(.eh_frame_hdr) }     :text  :eh_frame_hdr
  .eh_frame      : { KEEP (*(.eh_frame)) }  :text

  .dynamic       : { *(.dynamic) }          :text  :dynamic

  .rodata        : { *(.rodata*) }          :text

  . = ALIGN(0x1000);
  .text          : { *(.text*) }            :text    =0x03400000

  /*
   * No data / bss segment on purpose (matches vdso_arm64.lds). The
   * LoongArch VDSO carries clock_gettime data via the prepended parameter
   * page (`_params`), not a writable section in the VDSO ELF.
   */
}

PHDRS {
  text          PT_LOAD     FLAGS(5) FILEHDR PHDRS;  /* PF_R | PF_X */
  dynamic       PT_DYNAMIC  FLAGS(4);                /* PF_R */
  eh_frame_hdr  PT_GNU_EH_FRAME;
}

VERSION {
  LINUX_5.10 {
  global:
   __vdso_clock_getres;
   __vdso_clock_gettime;
   __vdso_gettimeofday;
   __vdso_rt_sigreturn;
   __kernel_rt_sigreturn;
   __vdso_getcpu;
  local: *;
  };
}
