#define _GNU_SOURCE
#include <dlfcn.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef long (*fn_create)(unsigned, const unsigned *);
typedef long (*fn_install)(long, void *, const unsigned char *, unsigned long,
                           unsigned, const int *, int, long long, int, int,
                           unsigned, const unsigned char *, const long long *,
                           const unsigned char *);

static uintptr_t main_base;

static int find_base(struct dl_phdr_info *info, size_t size, void *data)
{
    (void)size; (void)data;
    if (!info->dlpi_name || info->dlpi_name[0] == '\0') {
        main_base = (uintptr_t)info->dlpi_addr;
        return 1;
    }
    return 0;
}

__attribute__((constructor)) static void install_hook(void)
{
    dl_iterate_phdr(find_base, NULL);
    void *lib = dlopen("/tmp/libvg_int3.so", RTLD_NOW | RTLD_GLOBAL);
    if (!lib) {
        fprintf(stderr, "INT3 driver: dlopen failed: %s\n", dlerror());
        return;
    }
    fn_create create = (fn_create)dlsym(lib, "vg_ffi_patch_create");
    fn_install install = (fn_install)dlsym(lib, "vg_ffi_patch_install");
    if (!create || !install) {
        fprintf(stderr, "INT3 driver: dlsym failed\n");
        return;
    }
    /* mov r0, 1; exit => unconditional BLOCK */
    const unsigned char block[] = {0xB7,0x00,0,0,1,0,0,0, 0x95,0,0,0,0,0,0,0};
    long patch = create(0, NULL);
    long handle = install(patch, (void *)(main_base + 0xa3269),
                          block, sizeof(block), 0, NULL, 0, 0, 0, 0,
                          0, NULL, NULL, NULL);
    fprintf(stderr, "INT3 driver: base=%p patch=%ld handle=%ld\n",
            (void *)main_base, patch, handle);
}
