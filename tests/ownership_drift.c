/* Hold one unattached BPF object until the test closes the input pipe. */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <poll.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  struct bpf_object *object = bpf_object__open_file(argv[1], NULL);
  if (libbpf_get_error(object))
    return 1;
  int result = 1;
  if (bpf_object__load(object))
    goto cleanup;
  struct bpf_program *program =
      bpf_object__find_program_by_name(object, "unrelated_program");
  struct bpf_prog_info info = {0};
  unsigned int size = sizeof(info);
  if (!program ||
      bpf_prog_get_info_by_fd(bpf_program__fd(program), &info, &size) ||
      !info.id)
    goto cleanup;
  printf("%u\n", info.id);
  fflush(stdout);
  struct pollfd input = {.fd = STDIN_FILENO, .events = POLLIN};
  if (poll(&input, 1, 30000) <= 0)
    goto cleanup;
  result = 0;
cleanup:
  bpf_object__close(object);
  return result;
}
