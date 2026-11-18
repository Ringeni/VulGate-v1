#define _GNU_SOURCE
#include "trace.h"
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Episode controller and instrumented server threads serialize trace access. */
#define TRACE_LIMIT 1048576u
static uintptr_t pcs[TRACE_LIMIT], base;
static unsigned count, overflow, enabled;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

void vg_trace_begin(const void *symbol) {
    Dl_info info;
    if (!dladdr(symbol, &info)) abort();
    pthread_mutex_lock(&lock);
    base = (uintptr_t)info.dli_fbase;
    count = overflow = 0;
    enabled = 1;
    pthread_mutex_unlock(&lock);
}

void __sanitizer_cov_trace_pc(void) {
    uintptr_t pc = (uintptr_t)__builtin_return_address(0);
    Dl_info module;
    if (dladdr((void *)pc, &module)) {
        const unsigned char *name = (const unsigned char *)strrchr(module.dli_fname, '/');
        name = name ? name + 1 : (const unsigned char *)module.dli_fname;
        uint32_t hash = 2166136261u;
        for (; *name; ++name) hash = (hash ^ *name) * 16777619u;
        pc = ((uint64_t)hash << 32) | ((pc - (uintptr_t)module.dli_fbase) & 0xffffffffu);
    }
    pthread_mutex_lock(&lock);
    if (enabled) {
        if (count < TRACE_LIMIT) pcs[count++] = pc;
        else overflow = 1;
    }
    pthread_mutex_unlock(&lock);
}

void vg_trace_finish_json(FILE *out) {
    pthread_mutex_lock(&lock);
    enabled = 0;
    fprintf(out, "\"trace_complete\":%s,\"trace\":[", overflow ? "false" : "true");
    for (unsigned i = 0; i < count; ++i)
        fprintf(out, "%s%llu", i ? "," : "", (unsigned long long)pcs[i]);
    fputs("]", out);
    pthread_mutex_unlock(&lock);
}
