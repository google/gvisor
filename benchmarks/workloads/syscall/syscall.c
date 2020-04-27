// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// Short program that calls getpid() a number of times and outputs time
// diference from the MONOTONIC clock.
int main(int argc, char** argv) {
  struct timespec start, stop;
  long result;
  char buf[80];

  if (argc < 2) {
    printf("Usage:./syscall NUM_TIMES_TO_CALL");
    return 1;
  }

  if (clock_gettime(CLOCK_MONOTONIC, &start)) return 1;

  long loops = atoi(argv[1]);
  for (long i = 0; i < loops; i++) {
    syscall(SYS_gettimeofday, 0, 0);
  }

  if (clock_gettime(CLOCK_MONOTONIC, &stop)) return 1;

  if ((stop.tv_nsec - start.tv_nsec) < 0) {
    result = (stop.tv_sec - start.tv_sec - 1) * 1000;
    result += (stop.tv_nsec - start.tv_nsec + 1000000000) / (1000 * 1000);
  } else {
    result = (stop.tv_sec - start.tv_sec) * 1000;
    result += (stop.tv_nsec - start.tv_nsec) / (1000 * 1000);
  }

  printf("Called getpid syscall %d times: %lu ms, %lu ns each.\n", loops,
         result, result * 1000000 / loops);

  return 0;
}
