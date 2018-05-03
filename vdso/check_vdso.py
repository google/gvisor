# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Verify VDSO ELF does not contain any relocations and is directly mmappable.
"""

import argparse
import logging
import re
import subprocess

PAGE_SIZE = 4096


def PageRoundDown(addr):
  """Rounds down to the nearest page.

  Args:
    addr: An address.

  Returns:
    The address rounded down to thie nearest page.
  """
  return addr & ~(PAGE_SIZE - 1)


def Fatal(*args, **kwargs):
  """Logs a critical message and exits with code 1.

  Args:
    *args: Args to pass to logging.critical.
    **kwargs: Keyword args to pass to logging.critical.
  """
  logging.critical(*args, **kwargs)
  exit(1)


def CheckSegments(vdso_path):
  """Verifies layout of PT_LOAD segments.

  PT_LOAD segments must be laid out such that the ELF is directly mmappable.

  Specifically, check that:
  * PT_LOAD file offsets are equivalent to the memory offset from the first
    segment.
  * No extra zeroed space (memsz) is required.
  * PT_LOAD segments are in order (required for any ELF).
  * No two PT_LOAD segments share part of the same page.

  The readelf line format looks like:
  Type           Offset   VirtAddr           PhysAddr           FileSiz  MemSiz   Flg Align
  LOAD           0x000000 0xffffffffff700000 0xffffffffff700000 0x000e68 0x000e68 R E 0x1000

  Args:
    vdso_path: Path to VDSO binary.
  """
  output = subprocess.check_output(["readelf", "-lW", vdso_path]).decode()
  lines = output.split("\n")

  segments = []
  for line in lines:
    if not line.startswith("  LOAD"):
      continue

    components = line.split()

    segments.append({
        "offset": int(components[1], 16),
        "addr": int(components[2], 16),
        "filesz": int(components[4], 16),
        "memsz": int(components[5], 16),
    })

  if not segments:
    Fatal("No PT_LOAD segments in VDSO")

  first = segments[0]
  if first["offset"] != 0:
    Fatal("First PT_LOAD segment has non-zero file offset: %s", first)

  for i, segment in enumerate(segments):
    memoff = segment["addr"] - first["addr"]
    if memoff != segment["offset"]:
      Fatal("PT_LOAD segment has different memory and file offsets: %s",
            segments)

    if segment["memsz"] != segment["filesz"]:
      Fatal("PT_LOAD segment memsz != filesz: %s", segment)

    if i > 0:
      last_end = segments[i-1]["addr"] + segments[i-1]["memsz"]
      if segment["addr"] < last_end:
        Fatal("PT_LOAD segments out of order")

      last_page = PageRoundDown(last_end)
      start_page = PageRoundDown(segment["addr"])
      if last_page >= start_page:
        Fatal("PT_LOAD segments share a page: %s and %s", segment,
              segments[i - 1])


# Matches the section name in readelf -SW output.
_SECTION_NAME_RE = re.compile(r"""^\s+\[\ ?\d+\]\s+
                              (?P<name>\.\S+)\s+
                              (?P<type>\S+)\s+
                              (?P<addr>[0-9a-f]+)\s+
                              (?P<off>[0-9a-f]+)\s+
                              (?P<size>[0-9a-f]+)""", re.VERBOSE)


def CheckData(vdso_path):
  """Verifies the VDSO contains no .data or .bss sections.

  The readelf line format looks like:

  There are 15 section headers, starting at offset 0x15f0:

  Section Headers:
    [Nr] Name         Type      Address          Off    Size   ES Flg Lk Inf Al
    [ 0]              NULL      0000000000000000 000000 000000 00      0   0  0
    [ 1] .hash        HASH      ffffffffff700120 000120 000040 04   A  2   0  8
    [ 2] .dynsym      DYNSYM    ffffffffff700160 000160 000108 18   A  3   1  8
    ...
    [13] .strtab      STRTAB    0000000000000000 001448 000123 00      0   0  1
    [14] .shstrtab    STRTAB    0000000000000000 00156b 000083 00      0   0  1
  Key to Flags:
    W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
    L (link order), O (extra OS processing required), G (group), T (TLS),
    C (compressed), x (unknown), o (OS specific), E (exclude),
    l (large), p (processor specific)

  Args:
    vdso_path: Path to VDSO binary.
  """
  output = subprocess.check_output(["readelf", "-SW", vdso_path]).decode()
  lines = output.split("\n")

  found_text = False
  for line in lines:
    m = re.search(_SECTION_NAME_RE, line)
    if not m:
      continue

    if not line.startswith("  ["):
      continue

    name = m.group("name")
    size = int(m.group("size"), 16)

    if name == ".text" and size != 0:
      found_text = True

    # Clang will typically omit these sections entirely; gcc will include them
    # but with size 0.
    if name.startswith(".data") and size != 0:
      Fatal("VDSO contains non-empty .data section:\n%s" % output)

    if name.startswith(".bss") and size != 0:
      Fatal("VDSO contains non-empty .bss section:\n%s" % output)

  if not found_text:
    Fatal("VDSO contains no/empty .text section? Bad parsing?:\n%s" % output)


def CheckRelocs(vdso_path):
  """Verifies that the VDSO includes no relocations.

  Args:
    vdso_path: Path to VDSO binary.
  """
  output = subprocess.check_output(["readelf", "-r", vdso_path]).decode()
  if output.strip() != "There are no relocations in this file.":
    Fatal("VDSO contains relocations: %s", output)


def main():
  parser = argparse.ArgumentParser(description="Verify VDSO ELF.")
  parser.add_argument("--vdso", required=True, help="Path to VDSO ELF")
  parser.add_argument(
      "--check-data",
      action="store_true",
      help="Check that the ELF contains no .data or .bss sections")
  args = parser.parse_args()

  CheckSegments(args.vdso)
  CheckRelocs(args.vdso)

  if args.check_data:
    CheckData(args.vdso)


if __name__ == "__main__":
  main()
