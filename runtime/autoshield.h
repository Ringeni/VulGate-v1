#ifndef AUTOSHIELD_H
#define AUTOSHIELD_H

#ifdef __KERNEL__
#include <linux/types.h>

typedef u8 shadow_u8;
typedef u16 shadow_u16;
typedef u32 shadow_u32;
typedef s16 shadow_s16;
typedef s32 shadow_s32;
typedef u64 shadow_u64;
typedef s64 shadow_s64;
#else
#include <stddef.h>
#include <stdint.h>

typedef uint8_t shadow_u8;
typedef uint16_t shadow_u16;
typedef uint32_t shadow_u32;
typedef int16_t shadow_s16;
typedef int32_t shadow_s32;
typedef uint64_t shadow_u64;
typedef int64_t shadow_s64;
#endif

#define SHADOW_MAX_ARGS 6
#define SHADOW_MAX_REGS 16
#define SHADOW_MAX_SCRATCH 32
#define SHADOW_MAX_LOOP_BOUND 1024
#define SHADOW_MAX_PROGRAM_INSNS 4096
#define SHADOW_DEFAULT_STEP_LIMIT 4096
#define SHADOW_BLOCK_RETURN (-13)

#define SHADOW_HELPER_GET_ARG 1
#define SHADOW_HELPER_SAFE_READ_U8 2
#define SHADOW_HELPER_GET_REG 3
#define SHADOW_HELPER_SAFE_READ_U16 4
#define SHADOW_HELPER_SAFE_READ_U32 5
#define SHADOW_HELPER_SAFE_READ_U64 6
#define SHADOW_HELPER_SCRATCH_LOAD 7
#define SHADOW_HELPER_SCRATCH_STORE 8
#define SHADOW_HELPER_MAP_SET 9
#define SHADOW_HELPER_MAP_GET 10
#define SHADOW_HELPER_MAP_PRESENT 11
#define SHADOW_HELPER_MAP_DELETE 12
#define SHADOW_HELPER_SET_REG 13

#define SHADOW_MAX_MAPS 8

typedef struct shadow_map_entry {
    shadow_u64 key;
    shadow_u64 value;
    shadow_u8 used;
} shadow_map_entry;

typedef struct shadow_map {
    shadow_u32 capacity;
    shadow_u32 count;
    shadow_map_entry *entries;
} shadow_map;

int shadow_map_init(shadow_map *map, shadow_map_entry *entries, shadow_u32 capacity);
int shadow_map_get(const shadow_map *map, shadow_u64 key, shadow_u64 *value);
int shadow_map_set(shadow_map *map, shadow_u64 key, shadow_u64 value);
int shadow_map_present(const shadow_map *map, shadow_u64 key);
int shadow_map_delete(shadow_map *map, shadow_u64 key);

typedef enum shadow_decision {
    SHADOW_PASS = 0,
    SHADOW_BLOCK = 1,
    SHADOW_UNKNOWN = 2,
    SHADOW_VM_ERROR = 3,
} shadow_decision;

typedef enum shadow_unknown_mode {
    SHADOW_UNKNOWN_BLOCK = 0,
    SHADOW_UNKNOWN_PASS = 1,
} shadow_unknown_mode;

typedef enum shadow_status {
    SHADOW_STATUS_SAFE = 0,
    SHADOW_STATUS_UNSAFE = 1,
    SHADOW_STATUS_UNKNOWN = 2,
    SHADOW_STATUS_ERROR = 3,
} shadow_status;

typedef struct shadow_action {
    shadow_s64 value;
    const char *error;
    int disable_policy;
} shadow_action;

typedef struct shadow_policy_config {
    shadow_u64 step_limit;
    shadow_u64 max_call_depth;
    shadow_action unsafe_action;
    shadow_action unknown_action;
    shadow_action error_action;
} shadow_policy_config;

typedef struct shadow_ctx {
    shadow_u64 args[SHADOW_MAX_ARGS];
    shadow_u64 regs[SHADOW_MAX_REGS];
    shadow_map *maps;
    shadow_u32 map_count;
} shadow_ctx;

typedef struct shadow_policy {
    shadow_u64 step_limit;
    shadow_unknown_mode unknown_mode;
    shadow_s64 block_return;
} shadow_policy;

typedef struct shadow_stats {
    shadow_u64 instructions;
    shadow_u64 safe_reads;
    shadow_u64 helper_calls;
} shadow_stats;

typedef struct ebpf_insn {
    shadow_u8 code;
    shadow_u8 regs;
    shadow_s16 off;
    shadow_s32 imm;
} ebpf_insn;

struct shadow_program;

typedef shadow_decision (*ebpf_jit_fn)(const shadow_ctx *ctx,
                                      const struct shadow_program *program,
                                      const shadow_policy *policy,
                                      shadow_stats *stats);

typedef struct shadow_program {
    const ebpf_insn *insns;
    size_t len;
    ebpf_jit_fn jit_entry;
    void *jit_data;
} shadow_program;

void shadow_ctx_init(shadow_ctx *ctx);
void shadow_policy_init(shadow_policy *policy);

int shadow_program_init(const void *data, size_t size, shadow_program *program);
int shadow_program_validate(const shadow_program *program);
int shadow_program_max_steps(const shadow_program *program, shadow_u64 *out_steps);

#ifndef __KERNEL__
int shadow_program_load(const char *path, shadow_program *program);
void shadow_program_free(shadow_program *program);
#endif

shadow_decision run_ebpf_vm(const shadow_ctx *ctx,
                            const shadow_program *program,
                            const shadow_policy *policy,
                            shadow_stats *stats);

const char *shadow_decision_name(shadow_decision decision);

int safe_read(void *dst, const void *src, size_t len);

#endif
