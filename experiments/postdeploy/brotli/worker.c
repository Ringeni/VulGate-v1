/* Functional adapter: decodes only streams produced by the experiment encoder. */
#include <brotli/decode.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "trace.h"

static unsigned char *load(const char *path, size_t *length)
{
    FILE *f = fopen(path, "rb");
    if (!f || fseek(f, 0, SEEK_END)) exit(2);
    long size = ftell(f);
    if (size < 0 || size > 1048576 || fseek(f, 0, SEEK_SET)) exit(2);
    unsigned char *p = malloc((size_t)size + 1);
    if (!p || fread(p, 1, (size_t)size, f) != (size_t)size) exit(2);
    fclose(f);
    *length = (size_t)size;
    return p;
}

int main(void)
{
    char line[2200], compressed_path[1024], plain_path[1024];
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("{\"ready\":true}");
    while (fgets(line, sizeof(line), stdin)) {
        unsigned id, chunk_in, chunk_out, first_zero;
        if (!strncmp(line, "exit", 4)) return 0;
        if (sscanf(line, "%u %1023s %1023s %u %u %u", &id, compressed_path, plain_path,
                   &chunk_in, &chunk_out, &first_zero) != 6 || !chunk_in || !chunk_out) return 2;
        size_t encoded_size, expected_size;
        unsigned char *encoded = load(compressed_path, &encoded_size);
        unsigned char *expected = load(plain_path, &expected_size);
        size_t capacity = expected_size + 16;
        unsigned char *decoded = calloc(capacity, 1);
        if (!decoded) return 2;
        vg_trace_begin((const void *)&BrotliDecoderDecompressStream);
        BrotliDecoderState *s = BrotliDecoderCreateInstance(NULL, NULL, NULL);
        if (!s) return 2;
        const uint8_t *next_in = encoded;
        size_t available_in = 0, fed = 0, total_out = 0, produced = 0;
        unsigned calls = 0, needs_input = 0, needs_output = 0;
        BrotliDecoderResult result = BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT;
        while (calls < 100000) {
            if (!available_in && fed < encoded_size) {
                available_in = encoded_size - fed;
                if (available_in > chunk_in) available_in = chunk_in;
                next_in = encoded + fed;
                fed += available_in;
            }
            size_t available_out = capacity - produced;
            if (available_out > chunk_out) available_out = chunk_out;
            if (!calls && first_zero) available_out = 0;
            uint8_t *next_out = decoded + produced;
            result = BrotliDecoderDecompressStream(s, &available_in, &next_in,
                                                   &available_out, &next_out, &total_out);
            produced = (size_t)(next_out - decoded);
            calls++;
            if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT) needs_input++;
            if (result == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) needs_output++;
            if (result == BROTLI_DECODER_RESULT_SUCCESS || result == BROTLI_DECODER_RESULT_ERROR) break;
            if (produced == capacity || (result == BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT &&
                !available_in && fed == encoded_size)) break;
        }
        int error = BrotliDecoderGetErrorCode(s);
        BrotliDecoderDestroyInstance(s);
        printf("{\"case_id\":%u,\"result\":%d,\"error\":%d,\"calls\":%u,"
               "\"needs_input\":%u,\"needs_output\":%u,\"consumed\":%zu,"
               "\"produced\":%zu,\"total_out\":%zu,\"matches_expected\":%s,\"output_hex\":\"",
               id, result, error, calls, needs_input, needs_output, fed - available_in,
               produced, total_out, produced == expected_size && !memcmp(decoded, expected, produced) ? "true" : "false");
        for (size_t i = 0; i < produced; ++i) printf("%02x", decoded[i]);
        fputs("\",", stdout);
        vg_trace_finish_json(stdout);
        puts("}");
        free(decoded); free(expected); free(encoded);
    }
    return 0;
}
