// Copyright 2025 The gVisor Authors.
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

// This test validates the checkpoint/restore functionality for approximately
// 100 listening sockets operating in network=sandbox mode. It will create the
// sockets, accept all incoming connections, and then a checkpoint will be
// initiated from the other end. After restore, the test verifies that these
// listening sockets are correctly re-established and new client connections can
// be made.

#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define NUM_SOCKETS 100
#define START_PORT 9000
#define BACKLOG 10

// Structure to pass arguments to the listener thread
typedef struct {
  int port;
  int listen_fd;
} listener_arg_t;

void *listener_thread(void *arg) {
  listener_arg_t *listener_arg = (listener_arg_t *)arg;
  int port = listener_arg->port;
  int listen_fd = listener_arg->listen_fd;

  while (1) {
    printf("Listener on port %d started. Waiting for connection...\n", port);
    int client_fd = accept(listen_fd, NULL, NULL);
    if (errno == EINTR) {
      continue;
    }
    if (client_fd < 0) {
      perror("accept");
      exit(EXIT_FAILURE);
    }
    printf("Accepted connection on port %d\n", port);
    close(client_fd);
  }
}

int main() {
  struct sockaddr_in server_addr;
  int listen_fds[NUM_SOCKETS];
  pthread_t listener_threads[NUM_SOCKETS];
  int active_listeners = 0;
  int i;

  // Initialize listen_fds with -1 to indicate no socket yet
  for (i = 0; i < NUM_SOCKETS; ++i) {
    listen_fds[i] = -1;
  }

  printf("Attempting to create %d listening sockets starting from port %d...\n",
         NUM_SOCKETS, START_PORT);

  for (i = 0; i < NUM_SOCKETS; ++i) {
    int port = START_PORT + i;
    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
      perror("socket failed");
      exit(EXIT_FAILURE);
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) <
        0) {
      perror("bind failed");
      exit(EXIT_FAILURE);
    }
    if (listen(listen_fd, BACKLOG) < 0) {
      perror("listen failed");
      exit(EXIT_FAILURE);
    }
    printf("Successfully listening on port %d (FD: %d)\n", port, listen_fd);

    listen_fds[active_listeners] = listen_fd;
    active_listeners++;

    // Allocate memory for the argument to pass to the thread
    listener_arg_t *arg = (listener_arg_t *)malloc(sizeof(listener_arg_t));
    if (arg == NULL) {
      close(listen_fd);
      active_listeners--;
      exit(EXIT_FAILURE);
    }
    arg->port = port;
    arg->listen_fd = listen_fd;

    if (pthread_create(&listener_threads[i], NULL, listener_thread,
                       (void *)arg) != 0) {
      perror("pthread_create failed");
      close(listen_fd);
      free(arg);
      active_listeners--;
      exit(EXIT_FAILURE);
    }
  }

  // Wait for all threads to finish
  for (int i = 0; i < NUM_SOCKETS; i++) {
    if (pthread_join(listener_threads[i], NULL) != 0) {
      perror("failed to join thread");
      exit(EXIT_FAILURE);
    }
  }
  printf("Program finished.\n");
  return 0;
}
