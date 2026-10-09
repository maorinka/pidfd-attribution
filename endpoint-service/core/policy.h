#ifndef ENDPOINT_POLICY_H
#define ENDPOINT_POLICY_H
#define ENDPOINT_PREFIX_SIZE 80
/* Userspace may disable admission before detaching. BPF cannot modify policy.
 */
struct endpoint_policy {
  unsigned int enabled, capture_python, excluded_tgid, prefix_length;
  unsigned long long cgroup_id;
  char path_prefix[ENDPOINT_PREFIX_SIZE];
};
#endif
