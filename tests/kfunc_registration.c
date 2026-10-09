#include <bpf/libbpf.h>
#include <stdio.h>
int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  struct bpf_object *object = bpf_object__open_file(argv[1], NULL);
  if (libbpf_get_error(object))
    return 3;
  int result = bpf_object__load(object);
  printf("LOAD_RESULT %d\n", result);
  bpf_object__close(object);
  return result ? 1 : 0;
}
