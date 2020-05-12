#include <err.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int main(int argc, char** argv) {
  const char kTestFilePath[] = "testfile";
  const char kOldFileContents[] = "old data\n";
  const char kNewFileContents[] = "new data\n";
  const size_t kPageSize = sysconf(_SC_PAGE_SIZE);

  const int fd_rdonly = open(kTestFilePath, O_RDONLY);
  if (fd_rdonly < 0) {
    err(1, "open(%s, O_RDONLY)", kTestFilePath);
  }
  void* rdonly_page =
      mmap(NULL, kPageSize, PROT_READ, MAP_SHARED, fd_rdonly, 0);
  if (rdonly_page == MAP_FAILED) {
    err(1, "mmap");
  }
  if (strcmp(rdonly_page, kOldFileContents) != 0) {
    errx(1, "wrong initial file contents: %s", (const char*)rdonly_page);
  }

  const int fd_rdwr = open(kTestFilePath, O_RDWR);
  if (fd_rdwr < 0) {
    err(1, "open(%s, O_RDWR)", kTestFilePath);
  }
  // sizeof instead of strlen to also write the trailing NUL
  const ssize_t nr_written =
      write(fd_rdwr, kNewFileContents, sizeof(kNewFileContents));
  if (nr_written < 0) {
    err(1, "write");
  } else if (nr_written != sizeof(kNewFileContents)) {
    errx(1, "short write: wrote %ld / %lu bytes", nr_written,
         sizeof(kNewFileContents));
  }

  if (strcmp(rdonly_page, kNewFileContents) != 0) {
    errx(1, "wrong final file contents: %s", (const char*)rdonly_page);
  }

  return 0;
}
