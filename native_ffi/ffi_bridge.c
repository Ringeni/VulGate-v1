/* Independent INT3/SIGTRAP hook bridge for the VulGate Shadow VM.
 *
 * No funchook, libffi, or Frida hook engine is used. Frida (if any) is only the
 * loader. The first byte of each target is replaced with INT3; the SIGTRAP
 * handler runs every hook installed on that target from the saved ucontext.
 * PASS/observer single-steps the original instruction and re-inserts INT3;
 * BLOCK returns the action directly.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#include "runtime/autoshield.h"

#define VG_FFI_MAX_PATCHES 16
#define VG_FFI_MAX_HOOKS 64
#define VG_INT3_MAX_TARGETS 64

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

typedef struct vg_ffi_patch vg_ffi_patch;

typedef struct {
    void *target;
    shadow_program program;
    shadow_policy policy;
    unsigned nargs;
    vg_ffi_type arg_types[SHADOW_MAX_ARGS];
    vg_ffi_type return_type;
    uint64_t action;
    vg_ffi_nature nature;
    unsigned nlocals;
    unsigned char local_slots[8];
    long long local_offsets[8];
    unsigned char local_sizes[8];
    vg_ffi_patch *patch;
    int installed;
} vg_ffi_hook;

struct vg_ffi_patch {
    shadow_map maps[SHADOW_MAX_MAPS];
    shadow_map_entry *entries[SHADOW_MAX_MAPS];
    unsigned map_count;
    vg_ffi_hook hooks[VG_FFI_MAX_HOOKS];
    unsigned hook_count;
    int alive;
};

typedef struct {
    void *target;
    unsigned char original;
    unsigned refs;
} vg_target_entry;

static char vg_empty_string[1] = {0};
static vg_ffi_patch g_patches[VG_FFI_MAX_PATCHES];
static vg_target_entry g_targets[VG_INT3_MAX_TARGETS];
static struct sigaction g_old_trap;
static int g_trap_installed;
static __thread void *tls_pending_target;

static void patch_page(void *addr, int prot)
{
    long page = sysconf(_SC_PAGESIZE);
    uintptr_t start = (uintptr_t)addr & ~((uintptr_t)page - 1);
    mprotect((void *)start, (size_t)page, prot);
}

static void sync_code(void)
{
    /* x86 instruction fetch is coherent after mprotect+write on Linux, but a
     * compiler barrier and clear_cache document the ordering. */
    __sync_synchronize();
    __builtin___clear_cache((char *)0, (char *)0);
}

static vg_target_entry *target_find(void *target)
{
    for (unsigned i = 0; i < VG_INT3_MAX_TARGETS; i++) {
        if (g_targets[i].target == target && g_targets[i].refs) return &g_targets[i];
    }
    return NULL;
}

static void target_write(vg_target_entry *entry, unsigned char byte)
{
    patch_page(entry->target, PROT_READ | PROT_WRITE | PROT_EXEC);
    *(unsigned char *)entry->target = byte;
    patch_page(entry->target, PROT_READ | PROT_EXEC);
    sync_code();
}

static int target_acquire(void *target)
{
    vg_target_entry *entry = target_find(target);
    if (entry) {
        entry->refs++;
        return 0;
    }
    for (unsigned i = 0; i < VG_INT3_MAX_TARGETS; i++) {
        if (!g_targets[i].refs) {
            g_targets[i].target = target;
            g_targets[i].original = *(unsigned char *)target;
            g_targets[i].refs = 1;
            target_write(&g_targets[i], 0xCC);
            return 0;
        }
    }
    return -1;
}

static void target_release(void *target)
{
    vg_target_entry *entry = target_find(target);
    if (!entry) return;
    if (--entry->refs == 0) {
        target_write(entry, entry->original);
        memset(entry, 0, sizeof(*entry));
    }
}

static void target_suspend(void *target)
{
    vg_target_entry *entry = target_find(target);
    if (entry) target_write(entry, entry->original);
}

static void target_resume(void *target)
{
    vg_target_entry *entry = target_find(target);
    if (entry) target_write(entry, 0xCC);
}

static uint64_t x86_arg(const ucontext_t *uc, unsigned index, vg_ffi_type type)
{
    static const int regs[6] = {REG_RDI, REG_RSI, REG_RDX, REG_RCX, REG_R8, REG_R9};
    uint64_t raw;
    if (index < 6) {
        raw = (uint64_t)uc->uc_mcontext.gregs[regs[index]];
    } else {
        uintptr_t sp = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
        raw = *(uint64_t *)(sp + 8 + (index - 6) * 8);
    }
    switch (type) {
    case VG_TYPE_INT: return (uint64_t)(int64_t)(int32_t)raw;
    case VG_TYPE_UINT: return (uint64_t)(uint32_t)raw;
    default: return raw;
    }
}

static void set_return(ucontext_t *uc, vg_ffi_hook *hook)
{
    uint64_t value = hook->action;
    switch (hook->return_type) {
    case VG_TYPE_INT: uc->uc_mcontext.gregs[REG_RAX] = (greg_t)(int32_t)value; break;
    case VG_TYPE_UINT: uc->uc_mcontext.gregs[REG_RAX] = (greg_t)(uint32_t)value; break;
    case VG_TYPE_VOID: break;
    default: uc->uc_mcontext.gregs[REG_RAX] = (greg_t)value; break;
    }
    uintptr_t sp = (uintptr_t)uc->uc_mcontext.gregs[REG_RSP];
    uc->uc_mcontext.gregs[REG_RIP] = (greg_t)*(uintptr_t *)sp;
    uc->uc_mcontext.gregs[REG_RSP] = (greg_t)(sp + 8);
    uc->uc_mcontext.gregs[REG_EFL] &= ~(greg_t)0x100;
}

static void run_vm(vg_ffi_hook *hook, const ucontext_t *uc, shadow_decision *decision)
{
    shadow_ctx ctx;
    shadow_stats stats;
    shadow_ctx_init(&ctx);
    memset(&stats, 0, sizeof(stats));
    for (unsigned i = 0; i < hook->nargs && i < SHADOW_MAX_ARGS; i++) {
        ctx.args[i] = x86_arg(uc, i, hook->arg_types[i]);
    }
    if (hook->nlocals) {
        uintptr_t frame = (uintptr_t)uc->uc_mcontext.gregs[REG_RBP];
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
    ctx.maps = hook->patch->maps;
    ctx.map_count = hook->patch->map_count;
    *decision = run_ebpf_vm(&ctx, &hook->program, &hook->policy, &stats);
}

static void trap_handler(int sig, siginfo_t *info, void *ucontext_raw)
{
    (void)sig;
    (void)info;
    ucontext_t *uc = (ucontext_t *)ucontext_raw;
    if (tls_pending_target) {
        void *target = tls_pending_target;
        tls_pending_target = NULL;
        target_resume(target);
        return;
    }
    uintptr_t ip = (uintptr_t)uc->uc_mcontext.gregs[REG_RIP];
    int matched = 0;
    int blocked = 0;
    for (unsigned p = 0; p < VG_FFI_MAX_PATCHES && !blocked; p++) {
        if (!g_patches[p].alive) continue;
        for (unsigned h = 0; h < g_patches[p].hook_count; h++) {
            vg_ffi_hook *hook = &g_patches[p].hooks[h];
            if (!hook->installed || ip - 1 != (uintptr_t)hook->target) continue;
            matched = 1;
            shadow_decision decision;
            run_vm(hook, uc, &decision);
            if (hook->nature == VG_NATURE_GUARD &&
                (decision == SHADOW_BLOCK || decision == SHADOW_UNKNOWN ||
                 decision == SHADOW_VM_ERROR)) {
                set_return(uc, hook);
                blocked = 1;
                break;
            }
        }
    }
    if (!matched) {
        if (g_old_trap.sa_sigaction) g_old_trap.sa_sigaction(sig, info, ucontext_raw);
        return;
    }
    if (blocked) return;
    void *target = (void *)(ip - 1);
    target_suspend(target);
    uc->uc_mcontext.gregs[REG_EFL] |= 0x100;
    tls_pending_target = target;
}

static int install_sigaction(void)
{
    if (g_trap_installed) return 0;
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = trap_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    if (sigaction(SIGTRAP, &sa, &g_old_trap) != 0) return -1;
    g_trap_installed = 1;
    return 0;
}

__attribute__((visibility("default")))
long vg_ffi_patch_create(unsigned map_count, const unsigned *capacities)
{
    if (map_count > SHADOW_MAX_MAPS) return -1;
    int slot = -1;
    for (unsigned i = 0; i < VG_FFI_MAX_PATCHES; i++) {
        if (!g_patches[i].alive) { slot = (int)i; break; }
    }
    if (slot < 0) return -1;
    vg_ffi_patch *patch = &g_patches[slot];
    memset(patch, 0, sizeof(*patch));
    patch->map_count = map_count;
    patch->alive = 1;
    for (unsigned i = 0; i < map_count; i++) {
        unsigned capacity = capacities ? capacities[i] : 0;
        if (!capacity) capacity = 1;
        patch->entries[i] = calloc(capacity, sizeof(shadow_map_entry));
        if (!patch->entries[i]) return -2;
        if (shadow_map_init(&patch->maps[i], patch->entries[i], capacity) != 0) return -2;
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
        !target || !code || !code_len || nargs > SHADOW_MAX_ARGS) return -1;
    vg_ffi_patch *patch = &g_patches[patch_handle];
    if (!patch->alive || patch->hook_count >= VG_FFI_MAX_HOOKS) return -1;
    if (install_sigaction() != 0) return -3;
    unsigned hook_index = patch->hook_count;
    vg_ffi_hook *hook = &patch->hooks[hook_index];
    memset(hook, 0, sizeof(*hook));
    hook->patch = patch;
    hook->target = target;
    hook->nargs = nargs;
    hook->return_type = (vg_ffi_type)return_type;
    hook->action = action_kind == 1 ? (uint64_t)(uintptr_t)vg_empty_string : (uint64_t)action;
    hook->nature = (vg_ffi_nature)nature;
    hook->nlocals = nlocals > 8 ? 8 : nlocals;
    for (unsigned i = 0; i < hook->nlocals; i++) {
        hook->local_slots[i] = local_slots[i];
        hook->local_offsets[i] = local_offsets[i];
        hook->local_sizes[i] = local_sizes[i];
    }
    for (unsigned i = 0; i < nargs; i++) {
        hook->arg_types[i] = (vg_ffi_type)arg_types[i];
    }
    if (shadow_program_init(code, code_len, &hook->program) != 0 ||
        shadow_program_validate(&hook->program) != 0) return -2;
    shadow_policy_init(&hook->policy);
    hook->policy.step_limit = 4096;
    hook->installed = 1;
    patch->hook_count++;
    if (target_acquire(target) != 0) {
        hook->installed = 0;
        patch->hook_count--;
        return -5;
    }
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
        if (hook->installed) {
            hook->installed = 0;
            target_release(hook->target);
        }
    }
    for (unsigned i = 0; i < patch->map_count; i++) free(patch->entries[i]);
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
