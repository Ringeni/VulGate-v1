/* Standalone libffi bridge: funchook + libffi + Shadow VM.
 *
 * This is the experimental production path. Frida is used only as the
 * injector/loader; all per-hit work happens in this C library.
 */
#include <ffi.h>
#include <funchook.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "runtime/autoshield.h"

#define VG_FFI_MAX_PATCHES 16
#define VG_FFI_MAX_HOOKS 64

typedef enum {
    VG_TYPE_POINTER = 0,
    VG_TYPE_INT = 1,
    VG_TYPE_UINT = 2,
    VG_TYPE_INT64 = 3,
    VG_TYPE_UINT64 = 4,
    VG_TYPE_VOID = 5,
} vg_ffi_type;

typedef enum {
    VG_NATURE_GUARD = 0,
    VG_NATURE_OBSERVER = 1,
} vg_ffi_nature;

typedef struct {
    void *target;
    void *original;
    shadow_program program;
    shadow_policy policy;
    ffi_cif cif;
    ffi_type *ffi_args[SHADOW_MAX_ARGS];
    ffi_closure *closure;
    void *closure_code;
    funchook_t *funchook;
    unsigned nargs;
    vg_ffi_type return_type;
    uint64_t action;
    vg_ffi_nature nature;
    unsigned nlocals;
    unsigned char local_slots[8];
    long long local_offsets[8];
    unsigned char local_sizes[8];
    struct vg_ffi_patch *patch;
} vg_ffi_hook;

typedef struct vg_ffi_patch {
    shadow_map maps[SHADOW_MAX_MAPS];
    shadow_map_entry *entries[SHADOW_MAX_MAPS];
    unsigned map_count;
    vg_ffi_hook hooks[VG_FFI_MAX_HOOKS];
    unsigned hook_count;
    int alive;
} vg_ffi_patch;

static char vg_empty_string[1] = {0};
static vg_ffi_patch g_patches[VG_FFI_MAX_PATCHES];
static unsigned g_patch_count;

static ffi_type *ffi_type_for(vg_ffi_type type)
{
    switch (type) {
    case VG_TYPE_POINTER: return &ffi_type_pointer;
    case VG_TYPE_INT: return &ffi_type_sint32;
    case VG_TYPE_UINT: return &ffi_type_uint32;
    case VG_TYPE_INT64: return &ffi_type_sint64;
    case VG_TYPE_UINT64: return &ffi_type_uint64;
    case VG_TYPE_VOID: return &ffi_type_void;
    default: return NULL;
    }
}

static uint64_t read_arg(void *ptr, vg_ffi_type type)
{
    switch (type) {
    case VG_TYPE_INT: return (uint64_t)(int64_t)*(int32_t *)ptr;
    case VG_TYPE_UINT: return (uint64_t)*(uint32_t *)ptr;
    case VG_TYPE_INT64: return (uint64_t)*(int64_t *)ptr;
    case VG_TYPE_UINT64: return *(uint64_t *)ptr;
    case VG_TYPE_POINTER: return (uint64_t)(uintptr_t)*(void **)ptr;
    default: return 0;
    }
}

static void write_ret(void *ret, vg_ffi_type type, uint64_t value)
{
    switch (type) {
    case VG_TYPE_INT: *(int32_t *)ret = (int32_t)value; break;
    case VG_TYPE_UINT: *(uint32_t *)ret = (uint32_t)value; break;
    case VG_TYPE_INT64: *(int64_t *)ret = (int64_t)value; break;
    case VG_TYPE_UINT64: *(uint64_t *)ret = value; break;
    case VG_TYPE_POINTER: *(void **)ret = (void *)(uintptr_t)value; break;
    default: break;
    }
}

static void closure_handler(ffi_cif *cif, void *ret, void **args, void *user_data)
{
    vg_ffi_hook *hook = (vg_ffi_hook *)user_data;
    vg_ffi_type arg_types[SHADOW_MAX_ARGS];
    shadow_ctx ctx;
    shadow_stats stats;

    /* Argument type descriptors follow the hook in the sig table. */
    /* Stored in hook->ffi_args is ffi_type*, but we also need our own codes.
     * Keep the codes in a side table keyed by hook address. */
    extern unsigned char vg_ffi_arg_codes[VG_FFI_MAX_PATCHES][VG_FFI_MAX_HOOKS][SHADOW_MAX_ARGS];
    extern unsigned char vg_ffi_ret_codes[VG_FFI_MAX_PATCHES][VG_FFI_MAX_HOOKS];
    unsigned patch_index = (unsigned)(hook->patch - g_patches);
    unsigned hook_index = (unsigned)(hook - hook->patch->hooks);
    for (unsigned i = 0; i < hook->nargs && i < SHADOW_MAX_ARGS; i++) {
        arg_types[i] = (vg_ffi_type)vg_ffi_arg_codes[patch_index][hook_index][i];
    }

    shadow_ctx_init(&ctx);
    memset(&stats, 0, sizeof(stats));
    if (hook->nlocals) {
        uintptr_t frame = (uintptr_t)__builtin_frame_address(1);
        for (unsigned i = 0; i < hook->nlocals && i < 8; i++) {
            uintptr_t address = frame + (uintptr_t)hook->local_offsets[i];
            uint64_t value = 0;
            switch (hook->local_sizes[i]) {
            case 1: value = *(uint8_t *)address; break;
            case 2: value = *(uint16_t *)address; break;
            case 4: value = *(uint32_t *)address; break;
            default: value = *(uint64_t *)address; break;
            }
            ctx.regs[hook->local_slots[i]] = value;
        }
    }
    for (unsigned i = 0; i < hook->nargs && i < SHADOW_MAX_ARGS; i++) {
        ctx.args[i] = read_arg(args[i], arg_types[i]);
    }
    ctx.maps = hook->patch->maps;
    ctx.map_count = hook->patch->map_count;

    shadow_decision decision = run_ebpf_vm(&ctx, &hook->program, &hook->policy, &stats);
    vg_ffi_type ret_type = (vg_ffi_type)vg_ffi_ret_codes[patch_index][hook_index];
    if (getenv("VG_FFI_DEBUG")) {
        FILE *df = fopen("/tmp/vgffi-debug.log", "a");
        if (df) {
            fprintf(df, "VGFFI nargs=%u dec=%d", hook->nargs, (int)decision);
            for (unsigned i = 0; i < hook->nargs; i++) {
                fprintf(df, " a%u=%llx", i, (unsigned long long)ctx.args[i]);
            }
            if (hook->nargs > 0 && ctx.args[0]) {
                uintptr_t p0 = (uintptr_t)ctx.args[0];
                fprintf(df, " f40=%llx f1183=%x", (unsigned long long)*(uint64_t *)(p0 + 40),
                        *(uint32_t *)(p0 + 1183));
            }
            fprintf(df, "\n");
            fclose(df);
        }
    }

    if (hook->nature == VG_NATURE_OBSERVER) {
        ffi_call(cif, FFI_FN(hook->original), ret, args);
        return;
    }
    if (decision == SHADOW_BLOCK || decision == SHADOW_UNKNOWN || decision == SHADOW_VM_ERROR) {
        write_ret(ret, ret_type, hook->action);
        return;
    }
    ffi_call(cif, FFI_FN(hook->original), ret, args);
}

unsigned char vg_ffi_arg_codes[VG_FFI_MAX_PATCHES][VG_FFI_MAX_HOOKS][SHADOW_MAX_ARGS];
unsigned char vg_ffi_ret_codes[VG_FFI_MAX_PATCHES][VG_FFI_MAX_HOOKS];

__attribute__((visibility("default")))
long vg_ffi_patch_create(unsigned map_count, const unsigned *capacities)
{
    if (map_count > SHADOW_MAX_MAPS) {
        return -1;
    }
    int slot = -1;
    for (unsigned i = 0; i < VG_FFI_MAX_PATCHES; i++) {
        if (!g_patches[i].alive) {
            slot = (int)i;
            break;
        }
    }
    if (slot < 0) {
        return -1;
    }
    vg_ffi_patch *patch = &g_patches[slot];
    memset(patch, 0, sizeof(*patch));
    patch->map_count = map_count;
    patch->alive = 1;
    for (unsigned i = 0; i < map_count; i++) {
        unsigned capacity = capacities ? capacities[i] : 0;
        if (!capacity) capacity = 1;
        patch->entries[i] = calloc(capacity, sizeof(shadow_map_entry));
        if (!patch->entries[i]) return -2;
        if (shadow_map_init(&patch->maps[i], patch->entries[i], capacity) != 0) {
            return -2;
        }
    }
    return (long)slot;
}

__attribute__((visibility("default")))
long vg_ffi_patch_install(long patch_handle, void *target,
                          const unsigned char *code, size_t code_len,
                          unsigned nargs, const int *arg_types, int return_type,
                          long long action, int nature, int action_kind,
                          unsigned nlocals, const unsigned char *local_slots,
                          const long long *local_offsets, const unsigned char *local_sizes)
{
    if (patch_handle < 0 || (unsigned long)patch_handle >= VG_FFI_MAX_PATCHES ||
        !target || !code || !code_len || nargs > SHADOW_MAX_ARGS) {
        return -1;
    }
    vg_ffi_patch *patch = &g_patches[patch_handle];
    if (!patch->alive || patch->hook_count >= VG_FFI_MAX_HOOKS) {
        return -1;
    }
    unsigned patch_index = (unsigned)patch_handle;
    unsigned hook_index = patch->hook_count;
    vg_ffi_hook *hook = &patch->hooks[hook_index];
    memset(hook, 0, sizeof(*hook));
    hook->patch = patch;
    hook->target = target;
    hook->nargs = nargs;
    hook->return_type = (vg_ffi_type)return_type;
    hook->action = action_kind == 1
        ? (uint64_t)(uintptr_t)vg_empty_string
        : (uint64_t)action;
    hook->nature = (vg_ffi_nature)nature;
    hook->nlocals = nlocals > 8 ? 8 : nlocals;
    for (unsigned i = 0; i < hook->nlocals; i++) {
        hook->local_slots[i] = local_slots[i];
        hook->local_offsets[i] = local_offsets[i];
        hook->local_sizes[i] = local_sizes[i];
    }

    if (shadow_program_init(code, code_len, &hook->program) != 0 ||
        shadow_program_validate(&hook->program) != 0) {
        return -2;
    }
    shadow_policy_init(&hook->policy);
    hook->policy.step_limit = 4096;
    for (unsigned i = 0; i < nargs; i++) {
        vg_ffi_type type = (vg_ffi_type)arg_types[i];
        hook->ffi_args[i] = ffi_type_for(type);
        if (!hook->ffi_args[i]) return -3;
        vg_ffi_arg_codes[patch_index][hook_index][i] = (unsigned char)type;
    }
    vg_ffi_ret_codes[patch_index][hook_index] = (unsigned char)return_type;
    ffi_type *ret_type = ffi_type_for((vg_ffi_type)return_type);
    if (!ret_type) return -3;
    if (ffi_prep_cif(&hook->cif, FFI_DEFAULT_ABI, nargs, ret_type,
                     hook->ffi_args) != FFI_OK) {
        return -4;
    }
    hook->closure = ffi_closure_alloc(sizeof(ffi_closure), &hook->closure_code);
    if (!hook->closure) return -5;
    if (ffi_prep_closure_loc(hook->closure, &hook->cif, closure_handler,
                             hook, hook->closure_code) != FFI_OK) {
        return -6;
    }
    if (getenv("VG_FFI_HOOK_DEBUG")) funchook_set_debug_file("/tmp/funchook-debug.log");
    hook->funchook = funchook_create();
    if (!hook->funchook) return -7;
    hook->original = target;
    if (funchook_prepare(hook->funchook, &hook->original, hook->closure_code) != 0) {
        return -8;
    }
    if (funchook_install(hook->funchook, 0) != 0) {
        return -9;
    }
    patch->hook_count++;
    return (long)hook_index;
}

__attribute__((visibility("default")))
int vg_ffi_patch_destroy(long patch_handle)
{
    if (patch_handle < 0 || (unsigned long)patch_handle >= VG_FFI_MAX_PATCHES) return -1;
    vg_ffi_patch *patch = &g_patches[patch_handle];
    if (!patch->alive) return -1;
    for (unsigned i = 0; i < patch->hook_count; i++) {
        vg_ffi_hook *hook = &patch->hooks[i];
        if (hook->funchook) {
            funchook_uninstall(hook->funchook, 0);
            funchook_destroy(hook->funchook);
        }
        if (hook->closure) {
            ffi_closure_free(hook->closure);
        }
    }
    for (unsigned i = 0; i < patch->map_count; i++) {
        free(patch->entries[i]);
    }
    memset(patch, 0, sizeof(*patch));
    return 0;
}

__attribute__((visibility("default")))
unsigned vg_ffi_hook_count(void)
{
    unsigned total = 0;
    for (unsigned i = 0; i < VG_FFI_MAX_PATCHES; i++) {
        if (g_patches[i].alive) total += g_patches[i].hook_count;
    }
    return total;
}



