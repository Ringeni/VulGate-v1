#include "autoshield.h"

#ifdef __KERNEL__
#include <linux/errno.h>
#include <linux/string.h>
typedef unsigned long shadow_uintptr;
#else
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef uintptr_t shadow_uintptr;
#endif

#define VG_BPF_CLASS_MASK 0x07
#define VG_BPF_ALU 0x04
#define VG_BPF_JMP 0x05
#define VG_BPF_JMP32 0x06
#define VG_BPF_ALU64 0x07

#define VG_BPF_JA 0x05
#define VG_BPF_CALL 0x85
#define VG_BPF_EXIT 0x95

#define BPF_ADD_K32 0x04
#define BPF_ADD_X32 0x0C
#define BPF_ADD_K64 0x07
#define BPF_ADD_X64 0x0F
#define BPF_SUB_K32 0x14
#define BPF_SUB_X32 0x1C
#define BPF_SUB_K64 0x17
#define BPF_SUB_X64 0x1F
#define BPF_MUL_K32 0x24
#define BPF_MUL_X32 0x2C
#define BPF_MUL_K64 0x27
#define BPF_MUL_X64 0x2F
#define BPF_OR_K32 0x44
#define BPF_OR_X32 0x4C
#define BPF_OR_K64 0x47
#define BPF_OR_X64 0x4F
#define BPF_AND_K32 0x54
#define BPF_AND_X32 0x5C
#define BPF_AND_K64 0x57
#define BPF_AND_X64 0x5F
#define BPF_LSH_K32 0x64
#define BPF_LSH_X32 0x6C
#define BPF_LSH_K64 0x67
#define BPF_LSH_X64 0x6F
#define BPF_RSH_K32 0x74
#define BPF_RSH_X32 0x7C
#define BPF_RSH_K64 0x77
#define BPF_RSH_X64 0x7F
#define BPF_XOR_K32 0xA4
#define BPF_XOR_X32 0xAC
#define BPF_XOR_K64 0xA7
#define BPF_XOR_X64 0xAF
#define BPF_MOV_K32 0xB4
#define BPF_MOV_X32 0xBC
#define BPF_MOV_K64 0xB7
#define BPF_MOV_X64 0xBF

#define BPF_JEQ_K 0x15
#define BPF_JEQ_X 0x1D
#define BPF_JGT_K 0x25
#define BPF_JGT_X 0x2D
#define BPF_JGE_K 0x35
#define BPF_JGE_X 0x3D
#define BPF_JNE_K 0x55
#define BPF_JNE_X 0x5D
#define BPF_JSGT_K 0x65
#define BPF_JSGT_X 0x6D
#define BPF_JSGE_K 0x75
#define BPF_JSGE_X 0x7D
#define BPF_JLT_K 0xA5
#define BPF_JLT_X 0xAD
#define BPF_JLE_K 0xB5
#define BPF_JLE_X 0xBD
#define BPF_JSLT_K 0xC5
#define BPF_JSLT_X 0xCD
#define BPF_JSLE_K 0xD5
#define BPF_JSLE_X 0xDD

static shadow_u8 insn_dst(const ebpf_insn *insn)
{
    return insn->regs & 0x0F;
}

static shadow_u8 insn_src(const ebpf_insn *insn)
{
    return insn->regs >> 4;
}

static int is_jump_opcode(shadow_u8 code)
{
    shadow_u8 cls = code & VG_BPF_CLASS_MASK;
    return (cls == VG_BPF_JMP || cls == VG_BPF_JMP32) &&
           code != VG_BPF_CALL && code != VG_BPF_EXIT;
}

static int opcode_allowed(shadow_u8 code)
{
    switch (code) {
    case BPF_ADD_K32:
    case BPF_ADD_X32:
    case BPF_ADD_K64:
    case BPF_ADD_X64:
    case BPF_SUB_K32:
    case BPF_SUB_X32:
    case BPF_SUB_K64:
    case BPF_SUB_X64:
    case BPF_MUL_K32:
    case BPF_MUL_X32:
    case BPF_MUL_K64:
    case BPF_MUL_X64:
    case BPF_AND_K32:
    case BPF_AND_X32:
    case BPF_AND_K64:
    case BPF_AND_X64:
    case BPF_OR_K32:
    case BPF_OR_X32:
    case BPF_OR_K64:
    case BPF_OR_X64:
    case BPF_LSH_K32:
    case BPF_LSH_X32:
    case BPF_LSH_K64:
    case BPF_LSH_X64:
    case BPF_RSH_K32:
    case BPF_RSH_X32:
    case BPF_RSH_K64:
    case BPF_RSH_X64:
    case BPF_XOR_K32:
    case BPF_XOR_X32:
    case BPF_XOR_K64:
    case BPF_XOR_X64:
    case BPF_MOV_K32:
    case BPF_MOV_X32:
    case BPF_MOV_K64:
    case BPF_MOV_X64:
    case VG_BPF_JA:
    case BPF_JEQ_K:
    case BPF_JEQ_X:
    case BPF_JGT_K:
    case BPF_JGT_X:
    case BPF_JGE_K:
    case BPF_JGE_X:
    case BPF_JNE_K:
    case BPF_JNE_X:
    case BPF_JSGT_K:
    case BPF_JSGT_X:
    case BPF_JSGE_K:
    case BPF_JSGE_X:
    case BPF_JLT_K:
    case BPF_JLT_X:
    case BPF_JLE_K:
    case BPF_JLE_X:
    case BPF_JSLT_K:
    case BPF_JSLT_X:
    case BPF_JSLE_K:
    case BPF_JSLE_X:
    case VG_BPF_CALL:
    case VG_BPF_EXIT:
        return 1;
    default:
        return 0;
    }
}

int shadow_map_init(shadow_map *map, shadow_map_entry *entries, shadow_u32 capacity)
{
    if (!map || !entries || capacity == 0) return -1;
    for (shadow_u32 index = 0; index < capacity; index++) {
        entries[index].key = 0;
        entries[index].value = 0;
        entries[index].used = 0;
    }
    map->capacity = capacity;
    map->count = 0;
    map->entries = entries;
    return 0;
}

int shadow_map_get(const shadow_map *map, shadow_u64 key, shadow_u64 *value)
{
    if (!map || !map->entries || !value) return -1;
    for (shadow_u32 index = 0; index < map->capacity; index++) {
        if (map->entries[index].used && map->entries[index].key == key) {
            *value = map->entries[index].value;
            return 0;
        }
    }
    return -1;
}

int shadow_map_set(shadow_map *map, shadow_u64 key, shadow_u64 value)
{
    if (!map || !map->entries) return -1;
    for (shadow_u32 index = 0; index < map->capacity; index++) {
        if (map->entries[index].used && map->entries[index].key == key) {
            map->entries[index].value = value;
            return 0;
        }
    }
    for (shadow_u32 index = 0; index < map->capacity; index++) {
        if (!map->entries[index].used) {
            map->entries[index].used = 1;
            map->entries[index].key = key;
            map->entries[index].value = value;
            map->count++;
            return 0;
        }
    }
    return -2;
}

int shadow_map_present(const shadow_map *map, shadow_u64 key)
{
    shadow_u64 value = 0;
    return shadow_map_get(map, key, &value) == 0 ? 1 : 0;
}

int shadow_map_delete(shadow_map *map, shadow_u64 key)
{
    if (!map || !map->entries) return -1;
    for (shadow_u32 index = 0; index < map->capacity; index++) {
        if (map->entries[index].used && map->entries[index].key == key) {
            map->entries[index].used = 0;
            map->entries[index].value = 0;
            if (map->count > 0) map->count--;
            return 0;
        }
    }
    return -1;
}

static int helper_allowed(shadow_s32 helper_id)
{
    return helper_id == SHADOW_HELPER_GET_ARG ||
           helper_id == SHADOW_HELPER_SAFE_READ_U8 ||
           helper_id == SHADOW_HELPER_GET_REG ||
           helper_id == SHADOW_HELPER_SAFE_READ_U16 ||
           helper_id == SHADOW_HELPER_SAFE_READ_U32 ||
           helper_id == SHADOW_HELPER_SAFE_READ_U64 ||
           helper_id == SHADOW_HELPER_SCRATCH_LOAD ||
           helper_id == SHADOW_HELPER_SCRATCH_STORE ||
           helper_id == SHADOW_HELPER_MAP_SET ||
           helper_id == SHADOW_HELPER_MAP_GET ||
           helper_id == SHADOW_HELPER_MAP_PRESENT ||
           helper_id == SHADOW_HELPER_MAP_DELETE ||
           helper_id == SHADOW_HELPER_SET_REG;
}

static int validate_bounded_backedge(const shadow_program *program, size_t pc, size_t target)
{
    const ebpf_insn *latch = &program->insns[pc];
    const ebpf_insn *init_insn;
    const ebpf_insn *dec_insn;
    shadow_u8 reg_c = insn_dst(latch);
    size_t k;
    size_t j;

    if (latch->code != BPF_JGT_K || latch->imm != 0 || insn_src(latch) != 0) {
        return -EPERM;
    }
    if (reg_c == 0 || reg_c > 10 || target < 1 || pc < target + 1) {
        return -EPERM;
    }
    init_insn = &program->insns[target - 1];
    dec_insn = &program->insns[pc - 1];
    if (init_insn->code != BPF_MOV_K64 || insn_dst(init_insn) != reg_c ||
        init_insn->imm < 1 || init_insn->imm > SHADOW_MAX_LOOP_BOUND) {
        return -EPERM;
    }
    if (dec_insn->code != BPF_SUB_K64 || insn_dst(dec_insn) != reg_c || dec_insn->imm != 1) {
        return -EPERM;
    }
    for (k = target; k + 1 < pc; k++) {
        const ebpf_insn *body = &program->insns[k];
        shadow_u8 cls = body->code & VG_BPF_CLASS_MASK;
        if ((cls == VG_BPF_ALU || cls == VG_BPF_ALU64) && insn_dst(body) == reg_c) {
            return -EPERM;
        }
        if (body->code == VG_BPF_CALL && reg_c == 0) {
            return -EPERM;
        }
    }
    for (j = 0; j < program->len; j++) {
        const ebpf_insn *other = &program->insns[j];
        long jt;
        size_t dest;
        if (!is_jump_opcode(other->code)) {
            continue;
        }
        jt = (long)j + 1 + other->off;
        if (jt < 0 || (size_t)jt >= program->len) {
            return -EINVAL;
        }
        dest = (size_t)jt;
        if (dest == pc) {
            return -EPERM;
        }
        if ((j < target - 1 || j > pc) && dest >= target && dest <= pc) {
            return -EPERM;
        }
        if (j != pc && other->off < 0) {
            if (dest < 1) {
                return -EPERM;
            }
            if (!(j < target - 1 || dest - 1 > pc)) {
                int inner = (dest - 1 >= target && j + 2 <= pc);
                int outer = (j >= pc + 2 && target - 1 >= dest);
                if ((!inner && !outer) || insn_dst(other) == reg_c) {
                    return -EPERM;
                }
            }
        }
    }
    return 0;
}

void shadow_ctx_init(shadow_ctx *ctx)
{
    if (ctx) {
        memset(ctx, 0, sizeof(*ctx));
    }
}

void shadow_policy_init(shadow_policy *policy)
{
    if (!policy) {
        return;
    }
    policy->step_limit = SHADOW_DEFAULT_STEP_LIMIT;
    policy->unknown_mode = SHADOW_UNKNOWN_BLOCK;
    policy->block_return = SHADOW_BLOCK_RETURN;
}

const char *shadow_decision_name(shadow_decision decision)
{
    switch (decision) {
    case SHADOW_PASS:
        return "PASS";
    case SHADOW_BLOCK:
        return "BLOCK";
    case SHADOW_UNKNOWN:
        return "UNKNOWN";
    case SHADOW_VM_ERROR:
        return "VM_ERROR";
    default:
        return "INVALID";
    }
}

int shadow_program_init(const void *data, size_t size, shadow_program *program)
{
    if (!data || !program || size == 0 || size % sizeof(ebpf_insn) != 0) {
        return -EINVAL;
    }

    memset(program, 0, sizeof(*program));
    program->insns = (const ebpf_insn *)data;
    program->len = size / sizeof(ebpf_insn);
    return 0;
}

int shadow_program_validate(const shadow_program *program)
{
    size_t pc;

    if (!program || !program->insns || program->len == 0 ||
        program->len > SHADOW_MAX_PROGRAM_INSNS) {
        return -EINVAL;
    }

    for (pc = 0; pc < program->len; pc++) {
        const ebpf_insn *insn = &program->insns[pc];
        long target;

        if (!opcode_allowed(insn->code) || insn_dst(insn) > 10 || insn_src(insn) > 10) {
            return -EINVAL;
        }
        if (insn->code == VG_BPF_JA && (insn_dst(insn) != 0 || insn_src(insn) != 0 || insn->imm != 0)) {
            return -EINVAL;
        }

        if (insn->code == VG_BPF_CALL && !helper_allowed(insn->imm)) {
            return -EPERM;
        }

        if (is_jump_opcode(insn->code)) {
            target = (long)pc + 1 + insn->off;
            if (target < 0 || (size_t)target >= program->len) {
                return -EINVAL;
            }
            if (insn->off < 0) {
                int rc = validate_bounded_backedge(program, pc, (size_t)target);
                if (rc != 0) {
                    return rc;
                }
            }
        }
    }

    if (program->insns[program->len - 1].code != VG_BPF_EXIT) {
        return -EINVAL;
    }
    return 0;
}

int shadow_program_max_steps(const shadow_program *program, shadow_u64 *out_steps)
{
    size_t i;
    size_t pc;
    shadow_u64 total = 0;

    if (!out_steps) {
        return -EINVAL;
    }
    i = (size_t)shadow_program_validate(program);
    if ((int)i != 0) {
        return (int)i;
    }
    for (i = 0; i < program->len; i++) {
        shadow_u64 mult = 1;
        for (pc = i; pc < program->len; pc++) {
            const ebpf_insn *insn = &program->insns[pc];
            if (is_jump_opcode(insn->code) && insn->off < 0) {
                size_t target = (size_t)((long)pc + 1 + insn->off);
                if (i >= target && i <= pc) {
                    shadow_u64 bound = (shadow_u64)program->insns[target - 1].imm;
                    if (mult > ((shadow_u64)-1) / bound) {
                        return -EOVERFLOW;
                    }
                    mult *= bound;
                }
            }
        }
        if (total > ((shadow_u64)-1) - mult) {
            return -EOVERFLOW;
        }
        total += mult;
    }
    *out_steps = total;
    return 0;
}

#ifndef __KERNEL__
int shadow_program_load(const char *path, shadow_program *program)
{
    FILE *file;
    long size;
    size_t read_count;
    ebpf_insn *insns;
    int rc;

    if (!path || !program) {
        return -EINVAL;
    }

    file = fopen(path, "rb");
    if (!file) {
        return -errno;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return -errno;
    }
    size = ftell(file);
    if (size <= 0 || size % (long)sizeof(ebpf_insn) != 0) {
        fclose(file);
        return -EINVAL;
    }
    rewind(file);

    insns = (ebpf_insn *)calloc((size_t)size / sizeof(ebpf_insn), sizeof(ebpf_insn));
    if (!insns) {
        fclose(file);
        return -ENOMEM;
    }
    read_count = fread(insns, 1, (size_t)size, file);
    fclose(file);
    if (read_count != (size_t)size) {
        free(insns);
        return -EIO;
    }

    rc = shadow_program_init(insns, (size_t)size, program);
    if (rc == 0) {
        rc = shadow_program_validate(program);
    }
    if (rc != 0) {
        free(insns);
        memset(program, 0, sizeof(*program));
        return rc;
    }
    return 0;
}

void shadow_program_free(shadow_program *program)
{
    if (!program) {
        return;
    }
    free((void *)program->insns);
    program->insns = NULL;
    program->len = 0;
}
#endif

static int run_helper(shadow_u64 helper_id,
                      shadow_u64 regs[11],
                      shadow_u64 scratch[SHADOW_MAX_SCRATCH],
                      const shadow_ctx *ctx,
                      shadow_stats *stats)
{
    shadow_u8 v8 = 0;
    shadow_u16 v16 = 0;
    shadow_u32 v32 = 0;
    shadow_u64 v64 = 0;

    if (stats) {
        stats->helper_calls++;
    }

    switch (helper_id) {
    case SHADOW_HELPER_GET_ARG:
        if (regs[1] >= SHADOW_MAX_ARGS) {
            regs[0] = (shadow_u64)-1;
            return -1;
        }
        regs[0] = ctx->args[regs[1]];
        return 0;
    case SHADOW_HELPER_SAFE_READ_U8:
        if (stats) {
            stats->safe_reads++;
        }
        if (safe_read(&v8, (const void *)(shadow_uintptr)regs[1], sizeof(v8)) != 0) {
            regs[0] = (shadow_u64)-1;
            return -1;
        }
        regs[0] = v8;
        return 0;
    case SHADOW_HELPER_SAFE_READ_U16:
        if (stats) {
            stats->safe_reads++;
        }
        if (safe_read(&v16, (const void *)(shadow_uintptr)regs[1], sizeof(v16)) != 0) {
            regs[0] = (shadow_u64)-1;
            return -1;
        }
        regs[0] = v16;
        return 0;
    case SHADOW_HELPER_SAFE_READ_U32:
        if (stats) {
            stats->safe_reads++;
        }
        if (safe_read(&v32, (const void *)(shadow_uintptr)regs[1], sizeof(v32)) != 0) {
            regs[0] = (shadow_u64)-1;
            return -1;
        }
        regs[0] = v32;
        return 0;
    case SHADOW_HELPER_SAFE_READ_U64:
        if (stats) {
            stats->safe_reads++;
        }
        if (safe_read(&v64, (const void *)(shadow_uintptr)regs[1], sizeof(v64)) != 0) {
            regs[0] = (shadow_u64)-1;
            return -1;
        }
        regs[0] = v64;
        return 0;
    case SHADOW_HELPER_GET_REG:
        if (regs[1] >= SHADOW_MAX_REGS) {
            regs[0] = (shadow_u64)-1;
            return -1;
        }
        regs[0] = ctx->regs[regs[1]];
        return 0;
    case SHADOW_HELPER_SET_REG:
        if (regs[1] >= SHADOW_MAX_REGS) {
            regs[0] = (shadow_u64)-1;
            return -1;
        }
        ((shadow_ctx *)ctx)->regs[regs[1]] = regs[2];
        regs[0] = 0;
        return 0;
    case SHADOW_HELPER_SCRATCH_LOAD:
        if (regs[1] >= SHADOW_MAX_SCRATCH) {
            regs[0] = (shadow_u64)-1;
            return -1;
        }
        regs[0] = scratch[regs[1]];
        return 0;
    case SHADOW_HELPER_SCRATCH_STORE:
        if (regs[1] >= SHADOW_MAX_SCRATCH) {
            regs[0] = (shadow_u64)-1;
            return -1;
        }
        scratch[regs[1]] = regs[2];
        regs[0] = 0;
        return 0;
    case SHADOW_HELPER_MAP_SET:
        if (!ctx->maps || regs[1] >= ctx->map_count) {
            regs[0] = (shadow_u64)-1;
            return 0;
        }
        regs[0] = (shadow_u64)shadow_map_set(&ctx->maps[regs[1]], regs[2], regs[3]);
        return 0;
    case SHADOW_HELPER_MAP_GET: {
        shadow_u64 value = 0;
        if (!ctx->maps || regs[1] >= ctx->map_count ||
            shadow_map_get(&ctx->maps[regs[1]], regs[2], &value) != 0) {
            regs[0] = 0;
            return 0;
        }
        if (regs[3] != 0) {
            shadow_map_delete(&ctx->maps[regs[1]], regs[2]);
        }
        regs[0] = value;
        return 0;
    }
    case SHADOW_HELPER_MAP_PRESENT:
        if (!ctx->maps || regs[1] >= ctx->map_count) {
            regs[0] = 0;
            return 0;
        }
        regs[0] = (shadow_u64)shadow_map_present(&ctx->maps[regs[1]], regs[2]);
        return 0;
    case SHADOW_HELPER_MAP_DELETE:
        if (!ctx->maps || regs[1] >= ctx->map_count) {
            regs[0] = (shadow_u64)-1;
            return 0;
        }
        regs[0] = (shadow_u64)shadow_map_delete(&ctx->maps[regs[1]], regs[2]);
        return 0;
    default:
        regs[0] = SHADOW_VM_ERROR;
        return -1;
    }
}

static int should_jump(shadow_u8 code, shadow_u64 lhs, shadow_u64 rhs)
{
    switch (code) {
    case VG_BPF_JA:
        return 1;
    case BPF_JEQ_K:
    case BPF_JEQ_X:
        return lhs == rhs;
    case BPF_JGT_K:
    case BPF_JGT_X:
        return lhs > rhs;
    case BPF_JGE_K:
    case BPF_JGE_X:
        return lhs >= rhs;
    case BPF_JNE_K:
    case BPF_JNE_X:
        return lhs != rhs;
    case BPF_JSGT_K:
    case BPF_JSGT_X:
        return (shadow_s64)lhs > (shadow_s64)rhs;
    case BPF_JSGE_K:
    case BPF_JSGE_X:
        return (shadow_s64)lhs >= (shadow_s64)rhs;
    case BPF_JLT_K:
    case BPF_JLT_X:
        return lhs < rhs;
    case BPF_JLE_K:
    case BPF_JLE_X:
        return lhs <= rhs;
    case BPF_JSLT_K:
    case BPF_JSLT_X:
        return (shadow_s64)lhs < (shadow_s64)rhs;
    case BPF_JSLE_K:
    case BPF_JSLE_X:
        return (shadow_s64)lhs <= (shadow_s64)rhs;
    default:
        return 0;
    }
}

static shadow_decision run_ebpf_interpreter(const shadow_ctx *ctx,
                                            const shadow_program *program,
                                            const shadow_policy *policy,
                                            shadow_stats *stats)
{
    shadow_u64 regs[11] = {0};
    shadow_u64 scratch[SHADOW_MAX_SCRATCH] = {0};
    shadow_u64 step_limit = SHADOW_DEFAULT_STEP_LIMIT;
    shadow_u64 steps = 0;
    size_t pc = 0;

    if (!ctx || !program || !program->insns || program->len == 0) {
        return SHADOW_VM_ERROR;
    }
    if (policy && policy->step_limit > 0) {
        step_limit = policy->step_limit;
    }
    if (stats) {
        memset(stats, 0, sizeof(*stats));
    }

    regs[1] = (shadow_u64)(shadow_uintptr)ctx;

    while (pc < program->len) {
        const ebpf_insn *insn = &program->insns[pc];
        shadow_u8 dst = insn_dst(insn);
        shadow_u8 src = insn_src(insn);

        steps++;
        if (stats) {
            stats->instructions = steps;
        }
        if (steps > step_limit) {
            return SHADOW_UNKNOWN;
        }

        switch (insn->code) {
        case BPF_MOV_K32:
            regs[dst] = (shadow_u32)insn->imm;
            pc++;
            break;
        case BPF_MOV_X32:
            regs[dst] = (shadow_u32)regs[src];
            pc++;
            break;
        case BPF_MOV_K64:
            regs[dst] = (shadow_u64)(shadow_s64)insn->imm;
            pc++;
            break;
        case BPF_MOV_X64:
            regs[dst] = regs[src];
            pc++;
            break;
        case BPF_ADD_K32:
            regs[dst] = (shadow_u32)regs[dst] + (shadow_u32)insn->imm;
            pc++;
            break;
        case BPF_ADD_X32:
            regs[dst] = (shadow_u32)regs[dst] + (shadow_u32)regs[src];
            pc++;
            break;
        case BPF_ADD_K64:
            regs[dst] += (shadow_u64)(shadow_s64)insn->imm;
            pc++;
            break;
        case BPF_ADD_X64:
            regs[dst] += regs[src];
            pc++;
            break;
        case BPF_SUB_K32:
            regs[dst] = (shadow_u32)regs[dst] - (shadow_u32)insn->imm;
            pc++;
            break;
        case BPF_SUB_X32:
            regs[dst] = (shadow_u32)regs[dst] - (shadow_u32)regs[src];
            pc++;
            break;
        case BPF_SUB_K64:
            regs[dst] -= (shadow_u64)(shadow_s64)insn->imm;
            pc++;
            break;
        case BPF_SUB_X64:
            regs[dst] -= regs[src];
            pc++;
            break;
        case BPF_MUL_K32:
            regs[dst] = (shadow_u32)regs[dst] * (shadow_u32)insn->imm;
            pc++;
            break;
        case BPF_MUL_X32:
            regs[dst] = (shadow_u32)regs[dst] * (shadow_u32)regs[src];
            pc++;
            break;
        case BPF_MUL_K64:
            regs[dst] *= (shadow_u64)(shadow_s64)insn->imm;
            pc++;
            break;
        case BPF_MUL_X64:
            regs[dst] *= regs[src];
            pc++;
            break;
        case BPF_AND_K32:
            regs[dst] = (shadow_u32)regs[dst] & (shadow_u32)insn->imm;
            pc++;
            break;
        case BPF_AND_X32:
            regs[dst] = (shadow_u32)regs[dst] & (shadow_u32)regs[src];
            pc++;
            break;
        case BPF_AND_K64:
            regs[dst] &= (shadow_u64)(shadow_s64)insn->imm;
            pc++;
            break;
        case BPF_AND_X64:
            regs[dst] &= regs[src];
            pc++;
            break;
        case BPF_OR_K32:
            regs[dst] = (shadow_u32)regs[dst] | (shadow_u32)insn->imm;
            pc++;
            break;
        case BPF_OR_X32:
            regs[dst] = (shadow_u32)regs[dst] | (shadow_u32)regs[src];
            pc++;
            break;
        case BPF_OR_K64:
            regs[dst] |= (shadow_u64)(shadow_s64)insn->imm;
            pc++;
            break;
        case BPF_OR_X64:
            regs[dst] |= regs[src];
            pc++;
            break;
        case BPF_XOR_K32:
            regs[dst] = (shadow_u32)regs[dst] ^ (shadow_u32)insn->imm;
            pc++;
            break;
        case BPF_XOR_X32:
            regs[dst] = (shadow_u32)regs[dst] ^ (shadow_u32)regs[src];
            pc++;
            break;
        case BPF_XOR_K64:
            regs[dst] ^= (shadow_u64)(shadow_s64)insn->imm;
            pc++;
            break;
        case BPF_XOR_X64:
            regs[dst] ^= regs[src];
            pc++;
            break;
        case BPF_LSH_K32:
            regs[dst] = (shadow_u32)regs[dst] << ((shadow_u32)insn->imm & 31U);
            pc++;
            break;
        case BPF_LSH_X32:
            regs[dst] = (shadow_u32)regs[dst] << ((shadow_u32)regs[src] & 31U);
            pc++;
            break;
        case BPF_LSH_K64:
            regs[dst] <<= ((shadow_u64)insn->imm & 63ULL);
            pc++;
            break;
        case BPF_LSH_X64:
            regs[dst] <<= (regs[src] & 63ULL);
            pc++;
            break;
        case BPF_RSH_K32:
            regs[dst] = (shadow_u32)regs[dst] >> ((shadow_u32)insn->imm & 31U);
            pc++;
            break;
        case BPF_RSH_X32:
            regs[dst] = (shadow_u32)regs[dst] >> ((shadow_u32)regs[src] & 31U);
            pc++;
            break;
        case BPF_RSH_K64:
            regs[dst] >>= ((shadow_u64)insn->imm & 63ULL);
            pc++;
            break;
        case BPF_RSH_X64:
            regs[dst] >>= (regs[src] & 63ULL);
            pc++;
            break;
        case VG_BPF_JA:
        case BPF_JEQ_K:
        case BPF_JEQ_X:
        case BPF_JGT_K:
        case BPF_JGT_X:
        case BPF_JGE_K:
        case BPF_JGE_X:
        case BPF_JNE_K:
        case BPF_JNE_X:
        case BPF_JSGT_K:
        case BPF_JSGT_X:
        case BPF_JSGE_K:
        case BPF_JSGE_X:
        case BPF_JLT_K:
        case BPF_JLT_X:
        case BPF_JLE_K:
        case BPF_JLE_X:
        case BPF_JSLT_K:
        case BPF_JSLT_X:
        case BPF_JSLE_K:
        case BPF_JSLE_X:
            if (should_jump(insn->code,
                            regs[dst],
                            (insn->code & 0x08) ? regs[src] : (shadow_u64)(shadow_s64)insn->imm)) {
                long target = (long)pc + 1 + insn->off;
                if (target < 0 || (size_t)target >= program->len) {
                    return SHADOW_VM_ERROR;
                }
                pc = (size_t)target;
            } else {
                pc++;
            }
            break;
        case VG_BPF_CALL:
            if (run_helper((shadow_u64)insn->imm, regs, scratch, ctx, stats) != 0) {
                return SHADOW_UNKNOWN;
            }
            pc++;
            break;
        case VG_BPF_EXIT:
            if (regs[0] == SHADOW_PASS || regs[0] == SHADOW_BLOCK || regs[0] == SHADOW_UNKNOWN) {
                return (shadow_decision)regs[0];
            }
            return SHADOW_VM_ERROR;
        default:
            return SHADOW_VM_ERROR;
        }
    }

    return SHADOW_VM_ERROR;
}

shadow_decision run_ebpf_vm(const shadow_ctx *ctx,
                            const shadow_program *program,
                            const shadow_policy *policy,
                            shadow_stats *stats)
{
    if (program && program->jit_entry) {
        return program->jit_entry(ctx, program, policy, stats);
    }
    return run_ebpf_interpreter(ctx, program, policy, stats);
}
