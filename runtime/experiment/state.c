#include "state.h"
#include <string.h>

static int slot_key_eq(const vg_slot *slot, uint64_t scope, const uint64_t *key, unsigned key_words)
{
    unsigned i;
    if (!slot->used || slot->scope != scope || slot->key_words != key_words) return 0;
    for (i = 0; i < key_words; ++i)
        if (slot->keys[i] != key[i]) return 0;
    return 1;
}

static void write_slot(vg_slot *slot, uint64_t scope, const uint64_t *key, unsigned key_words,
                       const uint64_t *fields, unsigned nfields)
{
    unsigned i;
    memset(slot, 0, sizeof(*slot));
    slot->scope = scope;
    slot->key = key[0];
    slot->value = fields[0];
    slot->used = 1;
    slot->key_words = key_words;
    slot->nfields = nfields;
    for (i = 0; i < key_words; ++i) slot->keys[i] = key[i];
    for (i = 0; i < nfields; ++i) slot->fields[i] = fields[i];
}

int vg_table_set_words(vg_table *table, uint64_t scope, const uint64_t *key, unsigned key_words,
                       const uint64_t *fields, unsigned nfields)
{
    unsigned i, empty = table->capacity;
    if (!table || !key || !fields || key_words == 0 || key_words > VG_MAP_WORDS ||
        nfields == 0 || nfields > VG_MAP_WORDS)
        return -1;
    for (i = 0; i < table->capacity; ++i) {
        vg_slot *slot = &table->slots[i];
        if (slot_key_eq(slot, scope, key, key_words)) {
            write_slot(slot, scope, key, key_words, fields, nfields);
            return 0;
        }
        if (!slot->used && empty == table->capacity) empty = i;
    }
    if (empty == table->capacity) return -1;
    write_slot(&table->slots[empty], scope, key, key_words, fields, nfields);
    table->count++;
    return 0;
}

int vg_table_get_words(vg_table *table, uint64_t scope, const uint64_t *key, unsigned key_words,
                       uint64_t *fields, unsigned nfields, int consume)
{
    unsigned i, n;
    if (!table || !key || !fields || key_words == 0 || key_words > VG_MAP_WORDS ||
        nfields == 0 || nfields > VG_MAP_WORDS)
        return 0;
    for (i = 0; i < table->capacity; ++i) {
        vg_slot *slot = &table->slots[i];
        if (!slot_key_eq(slot, scope, key, key_words)) continue;
        n = slot->nfields < nfields ? slot->nfields : nfields;
        memset(fields, 0, nfields * sizeof(uint64_t));
        memcpy(fields, slot->fields, n * sizeof(uint64_t));
        if (consume) {
            memset(slot, 0, sizeof(*slot));
            if (table->count) table->count--;
        }
        return 1;
    }
    return 0;
}

int vg_table_set(vg_table *table, uint64_t scope, uint64_t key, uint64_t value)
{
    uint64_t keys[1] = {key};
    uint64_t fields[1] = {value};
    return vg_table_set_words(table, scope, keys, 1, fields, 1);
}

int vg_table_get(vg_table *table, uint64_t scope, uint64_t key, uint64_t *value, int consume)
{
    uint64_t keys[1] = {key};
    uint64_t fields[1] = {0};
    int found = vg_table_get_words(table, scope, keys, 1, fields, 1, consume);
    if (found && value) *value = fields[0];
    return found;
}

void vg_table_delete(vg_table *table, uint64_t scope, uint64_t key)
{
    uint64_t ignored;
    (void)vg_table_get(table, scope, key, &ignored, 1);
}

void vg_table_delete_words(vg_table *table, uint64_t scope, const uint64_t *key, unsigned key_words)
{
    unsigned i;
    if (!table || !key || key_words == 0 || key_words > VG_MAP_WORDS) return;
    for (i = 0; i < table->capacity; ++i) {
        vg_slot *slot = &table->slots[i];
        if (!slot_key_eq(slot, scope, key, key_words)) continue;
        memset(slot, 0, sizeof(*slot));
        if (table->count) table->count--;
        return;
    }
}
