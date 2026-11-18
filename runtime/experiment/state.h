#ifndef VG_EXPERIMENT_STATE_H
#define VG_EXPERIMENT_STATE_H
#include <stdint.h>
#include <stddef.h>

#define VG_MAP_WORDS 4

typedef struct vg_slot {
    uint64_t scope, key, value;
    unsigned used;
    unsigned key_words;
    unsigned nfields;
    uint64_t keys[VG_MAP_WORDS];
    uint64_t fields[VG_MAP_WORDS];
} vg_slot;
typedef struct vg_table { unsigned capacity, count; vg_slot *slots; } vg_table;
int vg_table_set(vg_table *, uint64_t scope, uint64_t key, uint64_t value);
int vg_table_get(vg_table *, uint64_t scope, uint64_t key, uint64_t *value, int consume);
void vg_table_delete(vg_table *, uint64_t scope, uint64_t key);
int vg_table_set_words(vg_table *, uint64_t scope, const uint64_t *key, unsigned key_words,
                       const uint64_t *fields, unsigned nfields);
int vg_table_get_words(vg_table *, uint64_t scope, const uint64_t *key, unsigned key_words,
                       uint64_t *fields, unsigned nfields, int consume);
void vg_table_delete_words(vg_table *, uint64_t scope, const uint64_t *key, unsigned key_words);
#endif
