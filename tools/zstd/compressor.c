// Copyright 2026 The gVisor Authors.
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

// This binary reads a tar stream on stdin and writes a zstd output to stdout.
// It is intended to be used as `compressor` for a pkg_tar rule.
// pkg_tar doesn't support zstd by default, and shelling out to the host's
// zstd CLI results in non-deterministic output.
//
// The parameters that work best for the release are also non-standard (but
// picked to still work with a default-implementation decoder).
//
// Specifically, we need:
//   - Level 22 with long-distance matching. This is because we include many
//     Go binaries (runsc, shim binary, metric server, sidecars) that share
//     many of the same libraries and the Go runtime itself, and anything
//     lower won't detect the overlap.
//     Level 22 has 20% smaller size vs the previous one, it's a very
//     measurable effect.
//   - windowLog at 27 (i.e. 128MiB). This is the largest window that stock
//     decoders (zstd -d, tar --zstd) can accept without a --long flag.
//     Required to detect duplication within the `runsc` binary (which is
//     large) together with the other Go binaries.
//   - Single-threaded, so output bytes are reproducible and do not depend on
//     the build machine.

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/zstd.h"

static void die(const char* msg) {
  fprintf(stderr, "compressor: %s\n", msg);
  exit(1);
}

static void set_param(ZSTD_CCtx* cctx, ZSTD_cParameter param, int value) {
  size_t ret = ZSTD_CCtx_setParameter(cctx, param, value);
  if (ZSTD_isError(ret)) die(ZSTD_getErrorName(ret));
}

static void write_all(const char* buf, size_t len) {
  while (len > 0) {
    ssize_t n = write(STDOUT_FILENO, buf, len);
    if (n < 0) {
      if (errno == EINTR) continue;
      die(strerror(errno));
    }
    buf += n;
    len -= n;
  }
}

int main(void) {
  ZSTD_CCtx* cctx = ZSTD_createCCtx();
  if (cctx == NULL) die("cannot create compression context");
  set_param(cctx, ZSTD_c_compressionLevel, 22);
  set_param(cctx, ZSTD_c_windowLog, 27);
  set_param(cctx, ZSTD_c_enableLongDistanceMatching, 1);
  set_param(cctx, ZSTD_c_checksumFlag, 1);

  size_t const in_cap = ZSTD_CStreamInSize();
  size_t const out_cap = ZSTD_CStreamOutSize();
  char* in = malloc(in_cap);
  char* out = malloc(out_cap);
  if (in == NULL || out == NULL) die("cannot allocate buffers");

  for (;;) {
    ssize_t n = read(STDIN_FILENO, in, in_cap);
    if (n < 0) {
      if (errno == EINTR) continue;
      die(strerror(errno));
    }
    ZSTD_EndDirective mode = n == 0 ? ZSTD_e_end : ZSTD_e_continue;
    ZSTD_inBuffer input = {in, (size_t)n, 0};
    for (;;) {
      ZSTD_outBuffer output = {out, out_cap, 0};
      size_t remaining = ZSTD_compressStream2(cctx, &output, &input, mode);
      if (ZSTD_isError(remaining)) die(ZSTD_getErrorName(remaining));
      write_all(out, output.pos);
      if (mode == ZSTD_e_end ? remaining == 0 : input.pos == input.size) {
        break;
      }
    }
    if (n == 0) return 0;
  }
}
