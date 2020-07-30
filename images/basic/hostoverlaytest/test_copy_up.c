#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char** argv) {
  const char kTestFilePath[] = "copy_up_testfile.txt";
  const char kOldFileData[] = "old data\n";
  const char kNewFileData[] = "new data\n";
  const size_t kPageSize = sysconf(_SC_PAGE_SIZE);

  // Open a file that already exists in a host overlayfs lower layer.
  const int fd_rdonly = open(kTestFilePath, O_RDONLY);
  if (fd_rdonly < 0) {
    err(1, "open(%s, O_RDONLY)", kTestFilePath);
  }

  // Check that the file's initial contents are what we expect when read via
  // syscall.
  char oldbuf[sizeof(kOldFileData)] = {};
  ssize_t n = pread(fd_rdonly, oldbuf, sizeof(oldbuf), 0);
  if (n < 0) {
    err(1, "initial pread");
  }
  if (n != strlen(kOldFileData)) {
    errx(1, "short initial pread (%ld/%lu bytes)", n, strlen(kOldFileData));
  }
  if (strcmp(oldbuf, kOldFileData) != 0) {
    errx(1, "initial pread returned wrong data: %s", oldbuf);
  }

  // Check that the file's initial contents are what we expect when read via
  // memory mapping.
  void* page = mmap(NULL, kPageSize, PROT_READ, MAP_SHARED, fd_rdonly, 0);
  if (page == MAP_FAILED) {
    err(1, "mmap");
  }
  if (strcmp(page, kOldFileData) != 0) {
    errx(1, "mapping contains wrong initial data: %s", (const char*)page);
  }

  // Open the same file writably, causing host overlayfs to copy it up, and
  // replace its contents.
  const int fd_rdwr = open(kTestFilePath, O_RDWR);
  if (fd_rdwr < 0) {
    err(1, "open(%s, O_RDWR)", kTestFilePath);
  }
  n = write(fd_rdwr, kNewFileData, strlen(kNewFileData));
  if (n < 0) {
    err(1, "write");
  }
  if (n != strlen(kNewFileData)) {
    errx(1, "short write (%ld/%lu bytes)", n, strlen(kNewFileData));
  }
  if (ftruncate(fd_rdwr, strlen(kNewFileData)) < 0) {
    err(1, "truncate");
  }

  int failed = 0;

  // Check that syscalls on the old FD return updated contents. (Before Linux
  // 4.18, this requires that runsc use a post-copy-up FD to service the read.)
  char newbuf[sizeof(kNewFileData)] = {};
  n = pread(fd_rdonly, newbuf, sizeof(newbuf), 0);
  if (n < 0) {
    err(1, "final pread");
  }
  if (n != strlen(kNewFileData)) {
    warnx("short final pread (%ld/%lu bytes)", n, strlen(kNewFileData));
    failed = 1;
  } else if (strcmp(newbuf, kNewFileData) != 0) {
    warnx("final pread returned wrong data: %s", newbuf);
    failed = 1;
  }

  // Check that the memory mapping of the old FD has been updated. (Linux
  // overlayfs does not do this, so regardless of kernel version this requires
  // that runsc replace existing memory mappings with mappings of a
  // post-copy-up FD.)
  if (strcmp(page, kNewFileData) != 0) {
    warnx("mapping contains wrong final data: %s", (const char*)page);
    failed = 1;
  }

  return failed;
}
