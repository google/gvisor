#include <dirent.h>
#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

int main(int argc, char** argv) {
  const char kDirPath[] = "rewinddir_test_dir";
  const char kFileBasename[] = "rewinddir_test_file";

  // Create the test directory.
  if (mkdir(kDirPath, 0755) < 0) {
    err(1, "mkdir(%s)", kDirPath);
  }

  // The test directory should initially be empty.
  DIR* dir = opendir(kDirPath);
  if (!dir) {
    err(1, "opendir(%s)", kDirPath);
  }
  int failed = 0;
  while (1) {
    errno = 0;
    struct dirent* d = readdir(dir);
    if (!d) {
      if (errno != 0) {
        err(1, "readdir");
      }
      break;
    }
    if (strcmp(d->d_name, ".") != 0 && strcmp(d->d_name, "..") != 0) {
      warnx("unexpected file %s in new directory", d->d_name);
      failed = 1;
    }
  }

  // Create a file in the test directory.
  char* file_path = malloc(strlen(kDirPath) + 1 + strlen(kFileBasename));
  if (!file_path) {
    errx(1, "malloc");
  }
  strcpy(file_path, kDirPath);
  file_path[strlen(kDirPath)] = '/';
  strcpy(file_path + strlen(kDirPath) + 1, kFileBasename);
  if (mknod(file_path, 0644, 0) < 0) {
    err(1, "mknod(%s)", file_path);
  }

  // After rewinddir(), re-reading the directory stream should yield the new
  // file.
  rewinddir(dir);
  size_t found_file = 0;
  while (1) {
    errno = 0;
    struct dirent* d = readdir(dir);
    if (!d) {
      if (errno != 0) {
        err(1, "readdir");
      }
      break;
    }
    if (strcmp(d->d_name, kFileBasename) == 0) {
      found_file++;
    } else if (strcmp(d->d_name, ".") != 0 && strcmp(d->d_name, "..") != 0) {
      warnx("unexpected file %s in new directory", d->d_name);
      failed = 1;
    }
  }
  if (found_file != 1) {
    warnx("readdir returned file %s %zu times, wanted 1", kFileBasename,
          found_file);
    failed = 1;
  }

  return failed;
}
