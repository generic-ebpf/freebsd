#pragma once
#include <sys/ebpf_vm_isa.h>
#ifdef _KERNEL
#include <sys/_ebpf.h>
#endif

#define EBPF_ENV_MAX 16
#define EBPF_PROG_LEN_MAX 4096

enum ebpf_env_types {
	EBPF_ENV_KERNEL
};

enum ebpf_prog_types {
	EBPF_PROG_TYPE_UNSPEC
};

enum ebpf_map_types {
	EBPF_MAP_TYPE_UNSPEC,
	EBPF_MAP_TYPE_ARRAY,
	EBPF_MAP_TYPE_HASH,
	EBPF_MAP_TYPE_PERCPU_ARRAY,
	EBPF_MAP_TYPE_PERCPU_HASH
};

enum ebpf_helper_types {
	EBPF_HELPER_TYPE_unspec,
	EBPF_HELPER_TYPE_map_lookup_elem,
	EBPF_HELPER_TYPE_map_update_elem,
	EBPF_HELPER_TYPE_map_delete_elem
};

struct ebpf_load_prog_req {
	uint32_t env;
	uint32_t type;
	uint32_t prog_len;
	void *prog;
	int *fdp;
};

struct ebpf_map_create_req {
	uint32_t env;
	uint32_t type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t max_entries;
	uint32_t flags;
	int *fdp;
};

struct ebpf_map_lookup_req {
	int fd;
	void *key;
	void *value;
};

struct ebpf_map_update_req {
	int fd;
	void *key;
	void *value;
	uint64_t flags;
};

struct ebpf_map_delete_req {
	int fd;
	void *key;
};

struct ebpf_map_get_next_key_req {
	int fd;
	void *key;
	void *next_key;
};

#define EBPFIOC_LOAD_PROG _IOWR('i', 151, struct ebpf_load_prog_req)
#define EBPFIOC_MAP_CREATE _IOWR('i', 152, struct ebpf_map_create_req)
#define EBPFIOC_MAP_LOOKUP_ELEM _IOWR('i', 153, struct ebpf_map_lookup_req)
#define EBPFIOC_MAP_UPDATE_ELEM _IOW('i', 154, struct ebpf_map_update_req)
#define EBPFIOC_MAP_DELETE_ELEM _IOW('i', 155, struct ebpf_map_delete_req)
#define EBPFIOC_MAP_GET_NEXT_KEY _IOWR('i', 156, struct ebpf_map_get_next_key_req)

#ifdef _KERNEL
int ebpf_env_register(uint32_t id, struct ebpf_env *ee);
struct ebpf_env *ebpf_env_unregister(uint32_t id);
#endif
