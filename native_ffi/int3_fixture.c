#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>

typedef long (*fn_install)(long, void *, const unsigned char *, unsigned long,
                           unsigned, const int *, int, long long, int, int,
                           unsigned, const unsigned char *, const long long *,
                           const unsigned char *);
typedef long (*fn_create)(unsigned, const unsigned *);
typedef int (*fn_destroy)(long);

static unsigned long long calls;

__attribute__((noinline)) static int target(int value)
{
    calls++;
    return value + 1;
}

static void run(const unsigned char *code, unsigned len, int action)
{
    void *lib = dlopen("./libvg_int3.so", RTLD_NOW);
    if (!lib) { printf("dlopen: %s\n", dlerror()); return; }
    fn_create create = (fn_create)dlsym(lib, "vg_ffi_patch_create");
    fn_install install = (fn_install)dlsym(lib, "vg_ffi_patch_install");
    fn_destroy destroy = (fn_destroy)dlsym(lib, "vg_ffi_patch_destroy");
    long patch = create(0, NULL);
    long handle = install(patch, target, code, len, 0, NULL, 1, action, 0, 0,
                          0, NULL, NULL, NULL);
    printf("patch=%ld handle=%ld\n", patch, handle);
    calls = 0;
    int result = target(10);
    printf("result=%d calls=%llu\n", result, calls);
    destroy(patch);
}

int main(void)
{
    const unsigned char block[] = {0xB7,0x00,0,0,1,0,0,0, 0x95,0,0,0,0,0,0,0};
    const unsigned char pass[] = {0xB7,0x00,0,0,0,0,0,0, 0x95,0,0,0,0,0,0,0};
    run(block, sizeof(block), -73);
    run(pass, sizeof(pass), 0);
    return 0;
}
