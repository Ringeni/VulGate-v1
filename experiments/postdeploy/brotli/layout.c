#include <stddef.h>
#include <stdio.h>
#include "state.h"

int main(void)
{
    printf("{\"remaining\":%zu,\"occupied\":%zu,\"capacity\":%zu,"
           "\"next_in\":%zu,\"last_in\":%zu,\"state_size\":%zu,\"fatal\":%d}\n",
           offsetof(BrotliDecoderState, meta_block_remaining_len),
           offsetof(BrotliDecoderState, buffer_length), sizeof(((BrotliDecoderState *)0)->buffer.u8),
           offsetof(BrotliDecoderState, br) + offsetof(BrotliBitReader, next_in),
           offsetof(BrotliDecoderState, br) + offsetof(BrotliBitReader, last_in),
           sizeof(BrotliDecoderState), BROTLI_DECODER_ERROR_FORMAT_BLOCK_LENGTH_1);
}
