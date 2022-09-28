// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

static int loops = 10000000;

static void show_usage(const char *cmd) {
  fprintf(stderr,
          "Usage: %s [options]\n"
          "-l, --loops <num>\t\t Number of syscall loops, default 10000000\n",
          cmd);
}

int main(int argc, char *argv[]) {
  int i;
  int c;
  struct option long_options[] = {{"loops", required_argument, 0, 'l'},
                                  {0, 0, 0, 0}};
  int option_index = 0;

  while ((c = getopt_long(argc, argv, "l:", long_options, &option_index)) !=
         -1) {
    switch (c) {
      case 'l':
        loops = atoi(optarg);
        if (loops <= 0) {
          show_usage(argv[0]);
          exit(1);
        }
        break;
      default:
        show_usage(argv[0]);
        exit(1);
    }
  }

  for (i = 0; i < loops; i++) syscall(SYS_getpid);

  printf("# Executed %'d getpid() calls\n", loops);
  return 0;
}
