#define _GNU_SOURCE
#include "trace.h"
#include <dlfcn.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define TRACE_LIMIT 1048576u
static uintptr_t pcs[TRACE_LIMIT];
static unsigned count, overflow, enabled;
static volatile int lock_word;

static void vg_lock(void)
{
    while (__sync_lock_test_and_set(&lock_word, 1)) {
        while (lock_word) {
        }
    }
}

static void vg_unlock(void)
{
    __sync_lock_release(&lock_word);
}

static uint64_t vg_module_pc(uintptr_t pc)
{
    Dl_info module;
    const unsigned char *name;
    uint32_t hash;
    if (!dladdr((void *)pc, &module) || module.dli_fname == NULL)
        return (uint64_t)pc;
    name = (const unsigned char *)strrchr(module.dli_fname, '/');
    name = name ? name + 1 : (const unsigned char *)module.dli_fname;
    hash = 2166136261u;
    for (; *name; ++name)
        hash = (hash ^ *name) * 16777619u;
    return ((uint64_t)hash << 32) | ((pc - (uintptr_t)module.dli_fbase) & 0xffffffffu);
}

void vg_trace_begin(const void *symbol)
{
    Dl_info info;
    if (!dladdr(symbol, &info))
        abort();
    vg_lock();
    count = overflow = 0;
    enabled = 1;
    vg_unlock();
}

void __sanitizer_cov_trace_pc(void)
{
    uint64_t encoded = vg_module_pc((uintptr_t)__builtin_return_address(0));
    vg_lock();
    if (enabled) {
        if (count < TRACE_LIMIT)
            pcs[count++] = (uintptr_t)encoded;
        else
            overflow = 1;
    }
    vg_unlock();
}

void vg_trace_finish_json(FILE *out)
{
    unsigned i;
    vg_lock();
    enabled = 0;
    fprintf(out, "\"trace_complete\":%s,\"trace\":[", overflow ? "false" : "true");
    for (i = 0; i < count; ++i)
        fprintf(out, "%s%llu", i ? "," : "", (unsigned long long)pcs[i]);
    fputs("]", out);
    vg_unlock();
}
