/* Read exact cumulative counters from the stable kernel BPF info ABI.
 * bpftool presentation may omit zero counters; the benchmark must not guess. */
#include <bpf/bpf.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc < 2 || argc > 65)
    return 2;
  putchar('[');
  for (int index = 1; index < argc; index++) {
    char *end;
    errno = 0;
    unsigned long id = strtoul(argv[index], &end, 10);
    if (errno || *argv[index] == '-' || !*argv[index] || *end || !id ||
        id > UINT_MAX)
      return 2;
    int fd = bpf_prog_get_fd_by_id((unsigned int)id);
    if (fd < 0) {
      perror("bpf_prog_get_fd_by_id");
      return 1;
    }
    struct bpf_prog_info info = {0};
    __u32 size = sizeof(info);
    int result = bpf_obj_get_info_by_fd(fd, &info, &size);
    int error = errno;
    close(fd);
    if (result || info.id != id) {
      errno = result ? error : EIO;
      perror("bpf_obj_get_info_by_fd");
      return 1;
    }
    printf("%s{\"id\":%u,\"run_time_ns\":%llu,\"run_cnt\":%llu}",
           index == 1 ? "" : ",", info.id, (unsigned long long)info.run_time_ns,
           (unsigned long long)info.run_cnt);
  }
  puts("]");
  return ferror(stdout) ? 1 : 0;
}
