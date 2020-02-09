.include <bsd.own.mk>

.PATH: ${.CURDIR}/../../dev/ebpf
.PATH.h: ${.CURDIR}/../../sys
KMOD    = ebpf
SRCS += ebpf_allocator.c
SRCS += ebpf_dev.c
SRCS += ebpf_env.c
SRCS += ebpf_freebsd.c
SRCS += ebpf_interpreter.c
SRCS += ebpf_map.c
SRCS += ebpf_map_array.c
SRCS += ebpf_map_hashtable.c
SRCS += ebpf_obj.c
SRCS += ebpf_prog.c

.include <bsd.kmod.mk>
