#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef uint64_t (*vg_u64_4_fn)(uint64_t, uint64_t, uint64_t, uint64_t);
typedef int (*vg_buf_fn)(const uint8_t *, size_t, uint8_t *, size_t *);

static int safe_symbol(const char *text) {
    if (!text || !text[0]) return 0;
    for (const char *p = text; *p; ++p) {
        char c = *p;
        int ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_';
        if (!ok) return 0;
    }
    return 1;
}

static int load_file(const char *path, uint8_t **data, size_t *length) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long size = ftell(fp);
    if (size < 0 || size > 1048576 || fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return -1;
    }
    uint8_t *buf = (uint8_t *)malloc((size_t)size + 1);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    if (size && fread(buf, 1, (size_t)size, fp) != (size_t)size) {
        free(buf);
        fclose(fp);
        return -1;
    }
    fclose(fp);
    *data = buf;
    *length = (size_t)size;
    return 0;
}

static void reject_call(void) {
    fputs("{\"call_ok\":false,\"return_u64\":0}\n", stdout);
    fflush(stdout);
}

static void emit_hex(const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; ++i) printf("%02x", data[i]);
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    void *library = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!library) {
        fprintf(stderr, "%s\n", dlerror());
        return 2;
    }
    setvbuf(stdout, NULL, _IONBF, 0);
    fputs("{\"ready\":true}\n", stdout);

    char line[8192];
    while (fgets(line, sizeof(line), stdin)) {
        if (!strncmp(line, "exit", 4)) {
            dlclose(library);
            return 0;
        }
        char symbol[128];
        char path[1024];
        unsigned long long a = 0, b = 0, c = 0, d = 0, cap = 0;
        if (sscanf(line, "u64_4 %127s %llu %llu %llu %llu", symbol, &a, &b, &c, &d) == 5) {
            if (!safe_symbol(symbol)) {
                reject_call();
                continue;
            }
            vg_u64_4_fn fn = (vg_u64_4_fn)dlsym(library, symbol);
            if (!fn) {
                printf("{\"convention\":\"u64_4\",\"symbol\":\"%s\",\"call_ok\":false,\"return_u64\":0}\n", symbol);
                continue;
            }
            uint64_t result = fn((uint64_t)a, (uint64_t)b, (uint64_t)c, (uint64_t)d);
            printf("{\"convention\":\"u64_4\",\"symbol\":\"%s\",\"call_ok\":true,\"return_u64\":%" PRIu64 "}\n",
                   symbol, result);
            continue;
        }
        if (sscanf(line, "buf_in_out %127s %1023s %llu", symbol, path, &cap) == 3) {
            uint8_t *input = NULL;
            size_t input_len = 0;
            if (!safe_symbol(symbol) || cap > 65536 || load_file(path, &input, &input_len) != 0) {
                reject_call();
                continue;
            }
            vg_buf_fn fn = (vg_buf_fn)dlsym(library, symbol);
            if (!fn) {
                free(input);
                printf("{\"convention\":\"buf_in_out\",\"symbol\":\"%s\",\"call_ok\":false,\"return_u64\":0}\n", symbol);
                continue;
            }
            uint8_t *output = (uint8_t *)calloc(cap ? (size_t)cap : 1, 1);
            size_t output_len = (size_t)cap;
            if (!output) {
                free(input);
                reject_call();
                continue;
            }
            int rc = fn(input, input_len, output, &output_len);
            if (output_len > cap) {
                free(output);
                free(input);
                printf("{\"convention\":\"buf_in_out\",\"symbol\":\"%s\",\"call_ok\":false,\"return_u64\":%d}\n", symbol, rc);
                continue;
            }
            printf("{\"convention\":\"buf_in_out\",\"symbol\":\"%s\",\"call_ok\":true,\"return_u64\":%d,\"output_hex\":\"",
                   symbol, rc);
            emit_hex(output, output_len);
            fputs("\"}\n", stdout);
            free(output);
            free(input);
            continue;
        }
        reject_call();
    }
    dlclose(library);
    return 0;
}
