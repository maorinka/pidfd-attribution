/* Calibrate before production attachment; child and links are always retired.
 */
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <signal.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>
struct observation {
  unsigned int kind, depth;
};
__attribute__((noinline, visibility("default"))) void
depth_target(unsigned int depth) {
  if (depth)
    depth_target(depth - 1);
  asm volatile("" ::: "memory");
}
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  int gate[2];
  if (pipe(gate))
    return 1;
  pid_t child = fork();
  if (child < 0) {
    close(gate[0]);
    close(gate[1]);
    return 1;
  }
  if (!child) {
    close(gate[1]);
    char byte;
    if (read(gate[0], &byte, 1) != 1)
      _exit(1);
    depth_target(1);
    _exit(0);
  }
  close(gate[0]);
  struct bpf_object *object = bpf_object__open_file(argv[1], NULL);
  struct bpf_link *links[2] = {0};
  int result = 1, status;
  if (libbpf_get_error(object)) {
    object = NULL;
    goto cleanup;
  }
  if (bpf_object__load(object))
    goto cleanup;
  struct bpf_program *loaded_program;
  bpf_object__for_each_program(loaded_program, object) {
    struct bpf_prog_info info = {0};
    unsigned int info_size = sizeof(info);
    if (bpf_prog_get_info_by_fd(bpf_program__fd(loaded_program), &info,
                                &info_size) ||
        !info.id)
      goto cleanup;
    fprintf(stderr, "IOSEC_OWNED_PROGRAM_ID=%u\n", info.id);
  }
  const char *names[] = {"depth_entry", "depth_return"};
  for (unsigned int i = 0; i < 2; i++) {
    struct bpf_program *program =
        bpf_object__find_program_by_name(object, names[i]);
    struct bpf_uprobe_opts options = {
        .sz = sizeof(options), .func_name = "depth_target", .retprobe = i != 0};
    if (!program)
      goto cleanup;
    links[i] = bpf_program__attach_uprobe_opts(program, child, "/proc/self/exe",
                                               0, &options);
    if (libbpf_get_error(links[i])) {
      links[i] = NULL;
      goto cleanup;
    }
  }
  if (write(gate[1], "x", 1) != 1)
    goto cleanup;
  if (waitpid(child, &status, 0) != child)
    goto cleanup;
  child = -1;
  if (!WIFEXITED(status) || WEXITSTATUS(status))
    goto cleanup;
  struct observation observed[5];
  int fd = bpf_object__find_map_fd_by_name(object, "observations");
  for (unsigned int i = 0; i < 5; i++)
    if (bpf_map_lookup_elem(fd, &i, &observed[i]))
      goto cleanup;
  if (observed[0].kind != 1 || observed[0].depth != 0 ||
      observed[1].kind != 1 || observed[1].depth != 1 ||
      observed[2].kind != 2 || observed[3].kind != 2 || observed[4].kind)
    goto cleanup;
  unsigned int bias = observed[3].depth;
  if (bias > 1 || observed[2].depth != bias + 1)
    goto cleanup;
  printf("{\"return_depth_bias\":%u,\"entry_depths\":[0,1],\"return_depths\":[%"
         "u,%u]}\n",
         bias, observed[2].depth, observed[3].depth);
  result = 0;
cleanup:
  if (child > 0) {
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
  }
  close(gate[1]);
  for (unsigned int i = 0; i < 2; i++)
    bpf_link__destroy(links[i]);
  bpf_object__close(object);
  return result;
}
