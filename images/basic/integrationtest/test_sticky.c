#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

void createFile(const char* path) {
  int fd = open(path, O_WRONLY | O_CREAT, 0777);
  if (fd < 0) {
    err(1, "open(%s)", path);
    exit(1);
  } else {
    close(fd);
  }
}

void waitAndCheckStatus(pid_t child) {
  int status;
  if (waitpid(child, &status, 0) == -1) {
    err(1, "waitpid() failed");
    exit(1);
  }

  if (WIFEXITED(status)) {
    int es = WEXITSTATUS(status);
    if (es) {
      err(1, "child exit status %d", es);
      exit(1);
    }
  } else {
    err(1, "child did not exit normally");
    exit(1);
  }
}

void deleteFile(uid_t user, const char* path) {
  pid_t child = fork();
  if (child == 0) {
    if (setuid(user)) {
      err(1, "setuid(%d)", user);
      exit(1);
    }

    if (unlink(path)) {
      err(1, "unlink(%s)", path);
      exit(1);
    }
    exit(0);
  }
  waitAndCheckStatus(child);
}

int main(int argc, char** argv) {
  const char kUser1Dir[] = "/user1dir";
  const char kUser2File[] = "/user1dir/user2file";
  const char kUser2File2[] = "/user1dir/user2file2";

  const uid_t user1 = 6666;
  const uid_t user2 = 6667;

  if (mkdir(kUser1Dir, 0755) != 0) {
    err(1, "mkdir(%s)", kUser1Dir);
    exit(1);
  }
  // Enable sticky bit for user1dir.
  if (chmod(kUser1Dir, 01777) != 0) {
    err(1, "chmod(%s)", kUser1Dir);
    exit(1);
  }
  createFile(kUser2File);
  createFile(kUser2File2);

  if (chown(kUser1Dir, user1, getegid())) {
    err(1, "chown(%s)", kUser1Dir);
    exit(1);
  }
  if (chown(kUser2File, user2, getegid())) {
    err(1, "chown(%s)", kUser2File);
    exit(1);
  }
  if (chown(kUser2File2, user2, getegid())) {
    err(1, "chown(%s)", kUser2File2);
    exit(1);
  }

  // User1 should be able to delete any file inside user1dir, even files of
  // other users due to the sticky bit.
  deleteFile(user1, kUser2File);

  // User2 should naturally be able to delete its own file even if the file is
  // inside a sticky dir owned by someone else.
  deleteFile(user2, kUser2File2);
}
