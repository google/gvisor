/*
 * Linker script for the VDSO.
 *
 * The VDSO is essentially a normal ELF shared library that is mapped into the
 * address space of the process that is going to use it. The address of the
 * VDSO is passed to the runtime linker in the AT_SYSINFO_EHDR entry of the aux
 * vector.
 *
 * There are, however, three ways in which the VDSO differs from a normal
 * shared library:
 *
 * - The runtime linker does not attempt to process any relocations for the
 *   VDSO so it is the responsibility of whoever loads the VDSO into the
 *   address space to do this if necessary. Because of this restriction we are
 *   careful to ensure that the VDSO does not need to have any relocations
 *   applied to it.
 *
 * - Although the VDSO is position independent and would normally be linked at
 *   virtual address 0, the Linux kernel VDSO is actually linked at a non zero
 *   virtual address and the code in the system runtime linker that handles the
 *   VDSO expects this to be the case so we have to explicitly link this VDSO
 *   at a non zero address. The actual address is arbitrary, but we use the
 *   same one as the Linux kernel VDSO.
 *
 * - The VDSO will be directly mmapped by the sentry, rather than going through
 *   a normal ELF loading process. The VDSO must be carefully constructed such
 *   that the layout in the ELF file is identical to the layout in memory.
 */

VDSO_PRELINK = 0xffffffffff700000;

OUTPUT_FORMAT("elf64-littleaarch64", "elf64-bigaarch64", "elf64-littleaarch64")
OUTPUT_ARCH(aarch64)

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

  .note          : { *(.note.*) }           :text  :note

  .eh_frame_hdr  : { *(.eh_frame_hdr) }     :text  :eh_frame_hdr
  .eh_frame      : { KEEP (*(.eh_frame)) }  :text

  .dynamic       : { *(.dynamic) }          :text  :dynamic

  .rodata        : { *(.rodata*) }          :text

  .altinstructions       : { *(.altinstructions) }
  .altinstr_replacement  : { *(.altinstr_replacement) }

  /*
   * TODO(gvisor.dev/issue/157): Remove this alignment? Then the VDSO would fit
   * in a single page.
   */
  . = ALIGN(0x1000);
  .text          : { *(.text*) }            :text    =0xd503201f

  /*
   * N.B. There is no data/bss section. This VDSO neither needs nor uses a data
   * section. We omit it entirely because some gcc/clang and gold/bfd version
   * combinations struggle to handle an empty data PHDR segment (internal
   * linker assertion failures result).
   *
   * If the VDSO does incorrectly include a data section, the linker will
   * include it in the text segment. check_vdso.py looks for this degenerate
   * case.
   */
}

PHDRS {
  text          PT_LOAD     FLAGS(5) FILEHDR PHDRS;  /* PF_R | PF_X */
  dynamic       PT_DYNAMIC  FLAGS(4);                /* PF_R */
  note          PT_NOTE     FLAGS(4);                /* PF_R */
  eh_frame_hdr  PT_GNU_EH_FRAME;
}

/*
 * Define the symbols that are to be exported.
 */
VERSION {
  LINUX_2.6.39 {
  global:
   __kernel_clock_getres;
   __kernel_clock_gettime;
   __kernel_gettimeofday;
   __kernel_rt_sigreturn;
  local: *;
  };
}
