#include <brotli/encode.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
    if (argc != 4) return 2;
    FILE *input = fopen(argv[1], "rb");
    if (!input || fseek(input, 0, SEEK_END)) return 2;
    long size = ftell(input);
    if (size < 0 || size > 1048576 || fseek(input, 0, SEEK_SET)) return 2;
    unsigned char *plain = malloc((size_t)size + 1);
    if (!plain || fread(plain, 1, (size_t)size, input) != (size_t)size) return 2;
    fclose(input);
    size_t capacity = BrotliEncoderMaxCompressedSize((size_t)size);
    unsigned char *encoded = malloc(capacity + 1);
    if (!encoded || !BrotliEncoderCompress(atoi(argv[3]), BROTLI_DEFAULT_WINDOW,
        BROTLI_MODE_GENERIC, (size_t)size, plain, &capacity, encoded)) return 2;
    FILE *output = fopen(argv[2], "wb");
    if (!output || fwrite(encoded, 1, capacity, output) != capacity) return 2;
    fclose(output);
    free(plain); free(encoded);
    return 0;
}
