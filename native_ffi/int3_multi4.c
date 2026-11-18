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

static unsigned long long calls[5];

__attribute__((noinline)) static int target1(int v) { calls[0]++; return v + 1; }
__attribute__((noinline)) static int target2(int v) { calls[1]++; return v + 2; }
__attribute__((noinline)) static int target3(int v) { calls[2]++; return v + 3; }
__attribute__((noinline)) static int target4(int v) { calls[3]++; return v + 4; }

int main(void)
{
    const unsigned char pass[] = {0xB7,0x00,0,0,0,0,0,0, 0x95,0,0,0,0,0,0,0};
    const unsigned char block[] = {0xB7,0x00,0,0,1,0,0,0, 0x95,0,0,0,0,0,0,0};
    void *lib = dlopen("./libvg_int3.so", RTLD_NOW);
    fn_create create = (fn_create)dlsym(lib, "vg_ffi_patch_create");
    fn_install install = (fn_install)dlsym(lib, "vg_ffi_patch_install");
    fn_destroy destroy = (fn_destroy)dlsym(lib, "vg_ffi_patch_destroy");
    long patch = create(0, NULL);

    /* 4 hooks on target1: three observers, then a guard. */
    for (int i = 0; i < 3; i++)
        printf("same-target observer %d=%ld\n", i,
               install(patch, target1, pass, sizeof(pass), 0, NULL, 1, 0, 1, 0, 0, NULL, NULL, NULL));
    printf("same-target guard=%ld\n",
           install(patch, target1, block, sizeof(block), 0, NULL, 1, -73, 0, 0, 0, NULL, NULL, NULL));

    /* Three more hooks on distinct targets. */
    printf("target2=%ld target3=%ld target4=%ld\n",
           install(patch, target2, block, sizeof(block), 0, NULL, 1, -72, 0, 0, 0, NULL, NULL, NULL),
           install(patch, target3, block, sizeof(block), 0, NULL, 1, -71, 0, 0, 0, NULL, NULL, NULL),
           install(patch, target4, block, sizeof(block), 0, NULL, 1, -70, 0, 0, 0, NULL, NULL, NULL));

    printf("t1=%d t2=%d t3=%d t4=%d\n", target1(10), target2(10), target3(10), target4(10));
    destroy(patch);
    printf("after t1=%d t2=%d t3=%d t4=%d\n", target1(10), target2(10), target3(10), target4(10));
    return 0;
}
