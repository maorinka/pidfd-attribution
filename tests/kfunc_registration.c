#include <bpf/libbpf.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
  if (argc != 3)
    return 2;
  struct bpf_object *object = bpf_object__open_file(argv[1], NULL);
  if (libbpf_get_error(object))
    return 3;
  struct bpf_program *program;
  int matched = 0;
  bpf_object__for_each_program(program, object) {
    bool selected = !strcmp(bpf_program__name(program), argv[2]);
    bpf_program__set_autoload(program, selected);
    matched += selected;
  }
  if (matched != 1) {
    bpf_object__close(object);
    return 4;
  }
  int result = bpf_object__load(object);
  printf("LOAD_RESULT %d\n", result);
  bpf_object__close(object);
  return result ? 1 : 0;
}
