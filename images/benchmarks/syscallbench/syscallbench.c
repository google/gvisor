// Copyright 2022 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdio.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <getopt.h>

static int loops = 10000000;

static void show_usage(const char *cmd)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"-l, --loops <num>\t\t Number of syscall loops, default 10000000\n", cmd);
	exit(1);
}

int main(int argc, char *argv[])
{
	struct timeval start, stop, diff;
	unsigned long long result_nsec = 0;
	int i;
	int c;
	struct option long_options[] = {
		{"loops", required_argument, 0, 'l'},
		{0, 0, 0, 0}};
	int option_index = 0;

	while ((c = getopt_long(argc, argv, "l:", long_options, &option_index)) != -1) {
		switch (c) {
		case 'l':
			loops = atoi(optarg);
			if (loops <= 0) {
				show_usage(argv[0]);
				exit(0);
			}
			break;
		default:
			show_usage(argv[0]);
			exit(0);
		}
	}

	gettimeofday(&start, NULL);

	for (i = 0; i < loops; i++)
		syscall(SYS_getpid);

	gettimeofday(&stop, NULL);
	timersub(&stop, &start, &diff);

	printf("# Executed %'d getpid() calls\n", loops);

	result_nsec = diff.tv_sec * 1000000000;
	result_nsec += diff.tv_usec * 1000;

	printf(" %14s: %lu.%03lu [sec]\n\n", "Total time",
	       diff.tv_sec, (unsigned long) (diff.tv_usec/1000));

	printf(" %14lf ns/syscall\n",
	       (double)result_nsec / (double)loops);
	printf(" %'14d syscalls/sec\n",
	       (int)((double)loops / ((double)result_nsec / (double)1000000000)));
	return 0;
}
