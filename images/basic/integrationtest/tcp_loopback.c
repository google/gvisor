#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define EXTERNAL_PORT 9000
#define LOCAL_PORT 9001

// Accept the connection and read.
int accept_and_read(int server_fd, struct sockaddr_in addr, int should_read) {
  int new_fd;
  socklen_t addrlen = sizeof(addr);

  while (1) {
    new_fd = accept(server_fd, (struct sockaddr*)&addr, &addrlen);
    if (new_fd >= 0) {
      break;
    }
    if (errno != EINTR) {
      perror("accept failed");
      exit(EXIT_FAILURE);
    }
  }

  if (new_fd < 0) {
    perror("accept failed");
    exit(EXIT_FAILURE);
  }

  if (should_read > 0) {
    for (int i = 0; i < 10; i++) {
      char buffer[1024] = {0};
      ssize_t valread = read(new_fd, buffer, 1024);
      if (valread <= 0) {
        perror("Server: read failed");
        exit(EXIT_FAILURE);
      }
      printf("Server received: %s", buffer);
    }
  }
  return new_fd;
}

int start_listen(struct sockaddr_in addr) {
  socklen_t addrlen = sizeof(addr);
  int server_fd;
  if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("Server: socket failed");
    exit(EXIT_FAILURE);
  }
  if (bind(server_fd, (struct sockaddr*)&addr, addrlen) < 0) {
    perror("Server: bind failed");
    exit(EXIT_FAILURE);
  }
  if (listen(server_fd, 2) < 0) {
    perror("Server: listen");
    exit(EXIT_FAILURE);
  }
  return server_fd;
}

int main() {
  // Start a listening socket on port 9001 which should be connected by a
  // loopback client.
  struct sockaddr_in address;
  address.sin_family = AF_INET;
  address.sin_port = htons(LOCAL_PORT);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  int local_fd = start_listen(address);
  int local_new_fd;

  pid_t pid = fork();
  if (pid < 0) {
    perror("fork failed");
    return 1;
  }
  if (pid == 0) {
    local_new_fd = accept_and_read(local_fd, address, 1 /* should_read */);
    return 1;
  }

  // Start a listening socket on port 9000 which should be connected by an
  // external client.
  struct sockaddr_in ext_addr;
  ext_addr.sin_family = AF_INET;
  ext_addr.sin_port = htons(EXTERNAL_PORT);
  ext_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  int ext_fd = start_listen(ext_addr);

  // Connect to the local loopback server.
  int connect_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (connect_fd < 0) {
    perror("Client: socket (Connect)");
    return 1;
  }
  int ret;
  do {
    ret = connect(connect_fd, (struct sockaddr*)&address, sizeof(address));
  } while (ret == -1 && errno == EINTR);
  if (ret < 0) {
    perror("Client: connect failed");
    exit(EXIT_FAILURE);
  }

  // Write and read with the loopback server.
  for (int i = 0; i < 10; i++) {
    const char* message = "Hello from Client 9000!\n";
    int num_sent = send(connect_fd, message, strlen(message), 0);
    if ((num_sent == -1) || (num_sent < strlen(message))) {
      perror("send failed");
      exit(EXIT_FAILURE);
    }
  }

  int ext_new_fd = accept_and_read(ext_fd, ext_addr, 0 /* should_read */);
  close(ext_new_fd);
  ext_new_fd = -1;

  // After connecting with the external server, a checkpoint is issued to the
  // sandbox. Everything below this happens after restore.
  ext_new_fd = accept_and_read(ext_fd, ext_addr, 0 /* should_read */);
  close(ext_new_fd);

  pid_t new_pid = fork();
  int restore_fd;
  if (new_pid < 0) {
    perror("fork failed");
    return 1;
  }
  if (new_pid == 0) {
    // Listening connections should be restored, start accepting new connections
    // after restore.
    restore_fd = accept_and_read(local_fd, address, 1 /* should_read */);
    return 1;
  }

  // connect_fd should be restored, read and write to the local server.
  for (int i = 0; i < 10; i++) {
    const char* message = "Hello from Client 9000!\n";
    int num_sent = send(connect_fd, message, strlen(message), 0);
    if ((num_sent == -1) || (num_sent < strlen(message))) {
      perror("send failed");
      exit(EXIT_FAILURE);
    }
  }
  printf("\nProgram finished successfully.\n");
  return 0;
}
