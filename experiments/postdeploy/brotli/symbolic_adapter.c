/* Typed entry-state adapter; the operation body is upstream source. */
#include "decode.c"

void pd_application(const uint64_t input[], uint64_t output[]) {
    BrotliDecoderState state;
    uint8_t ring[16], decoded[16] = {0}, buffered[16] = {0};
    for (unsigned i = 0; i < 16; ++i) ring[i] = (uint8_t)(i + 65);
    state.ringbuffer = ring;
    state.ringbuffer_size = 16;
    state.ringbuffer_mask = 15;
    state.window_bits = 4;
    state.pos = (int)input[0];
    state.partial_pos_out = 0;
    state.rb_roundtrips = 0;
    state.should_wrap_ringbuffer = 0;
    state.meta_block_remaining_len = (int)input[1];
    state.buffer_length = input[2];
    state.br.next_in = buffered;
    state.br.last_in = buffered + input[3];
    size_t available_out = input[5], total_out = 0;
    uint8_t *next_out = decoded;
    pd_record((uint64_t)(uintptr_t)&state, input[4]);
    output[0] = (uint64_t)(int64_t)WriteRingBuffer(
        &state, &available_out, &next_out, &total_out, BROTLI_TRUE);
    output[1] = available_out;
    output[2] = total_out;
    output[3] = state.partial_pos_out;
    output[4] = state.pos;
    output[5] = state.rb_roundtrips;
    output[6] = state.should_wrap_ringbuffer;
    output[7] = next_out - decoded;
    for (unsigned i = 0; i < 16; ++i) output[8 + i] = decoded[i];
}
