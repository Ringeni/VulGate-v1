from __future__ import annotations

import re
from collections import deque
from pathlib import Path
from typing import Any

from .oracle_compiler import (
    apply_episode_driver,
    apply_oracle_assertions,
    apply_snapshot_seed,
    episode_count,
    inject_allocator_obligations,
    inject_benign_impact_domain,
    inject_initial_map_state,
    inject_missing_callee_assert,
    inject_resource_balance,
    inject_poc_baseline_nonvacuity,
    included_layout_text,
)
from .snapshot_lifter import apply_snapshot_state


_ALLOCATOR_SITE_MACROS = (
    ('ngx_palloc', 'extern void *__vg_ngx_palloc(ngx_pool_t *pool, size_t size, unsigned callsite);\n#define ngx_palloc(pool, size) __vg_ngx_palloc((pool), (size), (unsigned)__LINE__)'),
    ('ngx_pnalloc', 'extern void *__vg_ngx_pnalloc(ngx_pool_t *pool, size_t size, unsigned callsite);\n#define ngx_pnalloc(pool, size) __vg_ngx_pnalloc((pool), (size), (unsigned)__LINE__)'),
    ('ngx_pcalloc', 'extern void *__vg_ngx_pcalloc(ngx_pool_t *pool, size_t size, unsigned callsite);\n#define ngx_pcalloc(pool, size) __vg_ngx_pcalloc((pool), (size), (unsigned)__LINE__)'),
    ('apr_palloc', 'extern void *__vg_apr_palloc(apr_pool_t *pool, apr_size_t size, unsigned callsite);\n#define apr_palloc(pool, size) __vg_apr_palloc((pool), (size), (unsigned)__LINE__)'),
    ('apr_brigade_create', 'extern apr_bucket_brigade *__vg_apr_brigade_create(apr_pool_t *p, apr_bucket_alloc_t *list, unsigned callsite);\n#define apr_brigade_create(pool, list) __vg_apr_brigade_create((pool), (list), (unsigned)__LINE__)'),
    ('apr_bucket_alloc', 'extern void *__vg_apr_bucket_alloc(apr_size_t size, apr_bucket_alloc_t *list, unsigned callsite);\n#define apr_bucket_alloc(size, list) __vg_apr_bucket_alloc((size), (list), (unsigned)__LINE__)'),
    ('_emalloc', 'extern void *__vg_emalloc(size_t size, unsigned callsite);\n#define _emalloc(size) __vg_emalloc((size), (unsigned)__LINE__)'),
    ('_safe_emalloc', 'extern void *__vg_safe_emalloc(size_t nmemb, size_t size, size_t offset, unsigned callsite);\n#define _safe_emalloc(nmemb, size, offset) __vg_safe_emalloc((nmemb), (size), (offset), (unsigned)__LINE__)'),
    ('_ecalloc', 'extern void *__vg_ecalloc(size_t nmemb, size_t size, unsigned callsite);\n#define _ecalloc(nmemb, size) __vg_ecalloc((nmemb), (size), (unsigned)__LINE__)'),
)


def _drop_function_definition(source: str, name: str) -> str:
    pattern = re.compile(rf'(?<![\w]){re.escape(name)}\s*\(')
    for match in pattern.finditer(source):
        close = _proto_match(source, match.end() - 1, '(', ')')
        if close < 0:
            continue
        cursor = close + 1
        while cursor < len(source) and source[cursor].isspace():
            cursor += 1
        if cursor >= len(source) or source[cursor] != '{':
            continue
        end = _matching_brace(source, cursor)
        if end is None:
            continue
        start = source.rfind('\n', 0, match.start()) + 1
        return source[:start] + source[end + 1:]
    return source


def allocator_model_for(family: str, slice_texts: list[str]) -> str:
    if family == 'nginx':
        text = NGINX_ENV_MODEL
        publics = [
            'ngx_palloc', 'ngx_pnalloc', 'ngx_pcalloc', 'ngx_pfree', 'ngx_log_error_core',
        ]
        if any(re.search(r'(?m)^ngx_uint_t\s+ngx_http_max_module\b', item) for item in slice_texts):
            text = text.replace('ngx_uint_t ngx_http_max_module = 16;\n', '')
        if any(re.search(r'(?m)^ngx_module_t\s+ngx_http_core_module\b', item) for item in slice_texts):
            text = text.replace('ngx_module_t ngx_http_core_module;\n', '')
    elif family == 'httpd':
        text = HTTPD_ENV_MODEL
        publics = [
            'apr_palloc', 'apr_brigade_create', 'apr_brigade_destroy', 'apr_brigade_cleanup',
            'apr_bucket_alloc_create', 'apr_bucket_alloc_destroy', 'apr_bucket_alloc',
            'apr_bucket_free', 'ap_log_rerror_', 'ap_log_cerror_', 'ap_log_error_',
        ]
    elif family == 'php':
        text = _php_allocator_c()
        publics = ['_emalloc', '_safe_emalloc', '_ecalloc', '_efree', '_zend_bailout']
    else:
        return ''
    for name in publics:
        if any(_function_definition_kind(item, name) for item in slice_texts):
            text = _drop_function_definition(text, name)
    return text


def stamp_allocator_callsites(source: str) -> str:
    macros = [
        text for name, text in _ALLOCATOR_SITE_MACROS
        if f'{name}(' in source and text not in source and not _function_definition_kind(source, name)
    ]
    if not macros:
        return source
    lines = source.split('\n')
    last_include = -1
    depth = 0
    in_inc_block = False
    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith('#'):
            if re.match(r'^#\s*(?:if|ifdef|ifndef)\b', stripped):
                depth += 1
            elif re.match(r'^#\s*endif\b', stripped):
                depth = max(0, depth - 1)
                if depth == 0 and in_inc_block:
                    last_include = index
                    in_inc_block = False
            elif re.match(r'^#\s*include\b', stripped):
                if depth == 0:
                    last_include = index
                else:
                    in_inc_block = True
        elif '{' in stripped and depth == 0 and last_include >= 0:
            break
    if last_include < 0:
        return '\n'.join([*macros, *lines])
    return '\n'.join([*lines[:last_include + 1], *macros, *lines[last_include + 1:]])


_FILE_SCOPE_DEF = re.compile(
    r'(?m)^(?:extern[ \t]+|inline[ \t]+)?'
    r'(?P<ret>[A-Za-z_][\w \t\*]*?)(?P<name>[A-Za-z_]\w*)\s*\((?P<params>[^;{}]*)\)\s*\{'
)
_SKIP_SLICE_NAMES = frozenset({'if', 'for', 'while', 'switch', 'main'})


def _matching_brace(source: str, open_at: int) -> int | None:
    depth = 0
    index = open_at
    while index < len(source):
        if source.startswith('//', index):
            newline = source.find('\n', index)
            index = len(source) if newline < 0 else newline + 1
            continue
        if source.startswith('/*', index):
            end = source.find('*/', index + 2)
            index = len(source) if end < 0 else end + 2
            continue
        if source[index] in ('"', "'"):
            quote = source[index]
            index += 1
            while index < len(source):
                if source[index] == '\\':
                    index += 2
                    continue
                if source[index] == quote:
                    index += 1
                    break
                index += 1
            continue
        if source[index] == '{':
            depth += 1
        elif source[index] == '}':
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return None


def file_scope_definitions(source: str) -> dict[str, tuple[int, int, str]]:
    found: dict[str, tuple[int, int, str]] = {}
    for match in _FILE_SCOPE_DEF.finditer(source):
        name = match.group('name')
        if name in _SKIP_SLICE_NAMES or name.startswith(('__vg_', '__vulgate_', '__CPROVER_', 'vg_')):
            continue
        if 'static' in match.group('ret').split():
            continue
        close = _matching_brace(source, match.end() - 1)
        if close is None:
            continue
        declarator = f'{match.group("ret").strip()} {name}({match.group("params").strip()})'
        found[name] = (match.start(), close + 1, declarator)
    return found


def prefer_slice_function_bodies(driver: str, slice_sources: list[str]) -> str:
    provided: set[str] = set()
    for source in slice_sources:
        provided.update(file_scope_definitions(source))
    if not provided:
        return driver
    replacements = []
    for name, (start, end, declarator) in file_scope_definitions(driver).items():
        if name not in provided:
            continue
        replacements.append((start, end, declarator + ';\n'))
    if not replacements:
        return driver
    rewritten = driver
    for start, end, text in sorted(replacements, key=lambda item: item[0], reverse=True):
        rewritten = rewritten[:start] + text + rewritten[end:]
    return rewritten


def _allocator_coupling_c() -> str:
    marks = (
        '    size_t __vg_mark_index;\n'
        '    __CPROVER_assume(size <= 8192u);\n'
        '    for (__vg_mark_index = 0; __vg_mark_index < size; ++__vg_mark_index)\n'
        '        __CPROVER_set_field(base + __vg_mark_index, "vulgate_uninitialized", dirty);'
    )
    dyn_reset = '\n'.join(f'        __vg_alloc_dyn[{index}] = 0;' for index in range(32))
    live_reset = '\n'.join(
        f'        __vg_live_base[{index}] = 0; __vg_live_size[{index}] = 0;' for index in range(16)
    )
    note_live = '\n'.join(
        f'    if (!__vg_live_base[{index}]) {{ __vg_live_base[{index}] = block; __vg_live_size[{index}] = size; return; }}'
        for index in range(16)
    )
    release_live = '\n'.join(
        '    if (__vg_live_base[{index}] == block) {{ __vg_mark_alloc((unsigned char *)block, __vg_live_size[{index}], 1); __vg_live_base[{index}] = 0; __vg_live_size[{index}] = 0; return; }}'.format(index=index)
        for index in range(16)
    )
    return f'''extern _Bool __vulgate_nondet_bool(void);
extern _Bool __vulgate_shadow_active;
static int __vg_alloc_epoch = -1;
static unsigned __vg_alloc_step;
static int __vg_alloc_bits_ready;
static _Bool __vg_alloc_fail_bit[16];
static unsigned __vg_alloc_dyn[32];
static unsigned char __vg_alloc_heap[4096];
static size_t __vg_alloc_cursor;
static _Bool __vg_alloc_double_free;
static _Bool __vg_alloc_lifetime_overflow;
static _Bool __vg_bailout_active;
static _Bool __vg_brigade_truncated;
static int __vg_resource_balance;
void __vg_resource_acquire(void) {{ __vg_resource_balance++; }}
void __vg_resource_release(void) {{
    if (__vg_resource_balance > 0) __vg_resource_balance--;
    else __vg_resource_balance = -1;
}}
static void *__vg_live_base[16];
static size_t __vg_live_size[16];

void __vg_alloc_enter_world(int epoch) {{
    if (__vg_alloc_epoch != epoch) {{
        __vg_alloc_epoch = epoch;
        __vg_alloc_step = 0;
        __vg_alloc_cursor = 0;
        __vg_alloc_double_free = 0;
        __vg_alloc_lifetime_overflow = 0;
        __vg_bailout_active = 0;
        __vg_brigade_truncated = 0;
        __vg_resource_balance = 0;
{dyn_reset}
{live_reset}
    }}
}}

void __vg_alloc_reset_process(void) {{
    __vg_alloc_step = 0;
    __vg_alloc_cursor = 0;
    __vg_alloc_double_free = 0;
    __vg_alloc_lifetime_overflow = 0;
    __vg_bailout_active = 0;
    __vg_brigade_truncated = 0;
    __vg_resource_balance = 0;
{dyn_reset}
{live_reset}
}}

int __vg_request_live_empty(void) {{
    return !(__vg_live_base[0] || __vg_live_base[1] || __vg_live_base[2] || __vg_live_base[3]
        || __vg_live_base[4] || __vg_live_base[5] || __vg_live_base[6] || __vg_live_base[7]
        || __vg_live_base[8] || __vg_live_base[9] || __vg_live_base[10] || __vg_live_base[11]
        || __vg_live_base[12] || __vg_live_base[13] || __vg_live_base[14] || __vg_live_base[15]);
}}

static _Bool __vg_alloc_should_fail(unsigned callsite) {{
    if (!__vg_alloc_bits_ready) {{
        __vg_alloc_bits_ready = 1;
        __vg_alloc_fail_bit[0] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[1] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[2] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[3] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[4] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[5] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[6] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[7] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[8] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[9] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[10] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[11] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[12] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[13] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[14] = __vulgate_nondet_bool();
        __vg_alloc_fail_bit[15] = __vulgate_nondet_bool();
    }}
    unsigned bucket = callsite & 31u;
    unsigned dyn = __vg_alloc_dyn[bucket];
    if (dyn < 255u) __vg_alloc_dyn[bucket] = dyn + 1u;
    unsigned slot = ((callsite * 131u) ^ dyn) & 15u;
    return __vg_alloc_fail_bit[slot];
}}

static void __vg_mark_alloc(unsigned char *base, size_t size, _Bool dirty) {{
    if (!__vulgate_shadow_active || !base) return;
{marks}
}}

static void __vg_note_live(void *block, size_t size) {{
{note_live}
    __vg_alloc_lifetime_overflow = 1;
}}

static void __vg_release_live(void *block) {{
    if (!block) return;
{release_live}
    __vg_alloc_double_free = 1;
}}

static void *__vg_heap_alloc(size_t size, _Bool dirty, unsigned callsite) {{
    if (!size || size > 256 || __vg_alloc_should_fail(callsite)) return NULL;
    if (__vg_alloc_cursor + size > sizeof(__vg_alloc_heap)) return NULL;
    unsigned char *block = __vg_alloc_heap + __vg_alloc_cursor;
    __vg_alloc_cursor += size;
    __vg_mark_alloc(block, size, dirty);
    __vg_note_live(block, size);
    return block;
}}
'''


def _php_allocator_c() -> str:
    return _allocator_coupling_c() + '''
void *__vg_emalloc(size_t size, unsigned callsite) { return __vg_heap_alloc(size, 1, callsite); }
void *_emalloc(size_t size) { return __vg_emalloc(size, 0); }
void *__vg_safe_emalloc(size_t nmemb, size_t size, size_t offset, unsigned callsite) {
    if (size && nmemb > (((size_t)-1) - offset) / size) return NULL;
    return __vg_heap_alloc(nmemb * size + offset, 1, callsite);
}
void *_safe_emalloc(size_t nmemb, size_t size, size_t offset) { return __vg_safe_emalloc(nmemb, size, offset, 0); }
void *__vg_ecalloc(size_t nmemb, size_t size, unsigned callsite) {
    if (size && nmemb > ((size_t)-1) / size) return NULL;
    void *block = __vg_heap_alloc(nmemb * size, 0, callsite);
    if (block && nmemb && size) memset(block, 0, nmemb * size);
    return block;
}
void *_ecalloc(size_t nmemb, size_t size) { return __vg_ecalloc(nmemb, size, 0); }
void _efree(void *ptr) { __vg_release_live(ptr); }
void _zend_bailout(const char *filename, unsigned lineno) {
    (void)filename; (void)lineno;
    __vg_bailout_active = 1;
    __CPROVER_assume(0);
}
'''


NGINX_ENV_MODEL = '''
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_uint_t ngx_http_max_module = 16;
ngx_module_t ngx_http_core_module;

''' + _allocator_coupling_c() + '''

void *__vg_ngx_palloc(ngx_pool_t *pool, size_t size, unsigned callsite) {
    if (!pool || size > 256 || __vg_alloc_should_fail(callsite)) return NULL;
    if ((size_t)(pool->d.end - pool->d.last) < size) return NULL;
    u_char *m = pool->d.last;
    pool->d.last += size;
    __vg_mark_alloc(m, size, 1);
    return m;
}
void *ngx_palloc(ngx_pool_t *pool, size_t size) { return __vg_ngx_palloc(pool, size, 0); }
void *__vg_ngx_pnalloc(ngx_pool_t *pool, size_t size, unsigned callsite) { return __vg_ngx_palloc(pool, size, callsite); }
void *ngx_pnalloc(ngx_pool_t *pool, size_t size) { return __vg_ngx_pnalloc(pool, size, 0); }
void *__vg_ngx_pcalloc(ngx_pool_t *pool, size_t size, unsigned callsite) {
    void *m = __vg_ngx_palloc(pool, size, callsite);
    if (m) {
        memset(m, 0, size);
        __vg_mark_alloc((unsigned char *)m, size, 0);
    }
    return m;
}
void *ngx_pcalloc(ngx_pool_t *pool, size_t size) { return __vg_ngx_pcalloc(pool, size, 0); }
ngx_int_t ngx_pfree(ngx_pool_t *pool, void *p) { (void)pool; (void)p; return NGX_OK; }
void ngx_log_error_core(ngx_uint_t level, ngx_log_t *log, ngx_err_t err, const char *fmt, ...) {
    (void)level; (void)log; (void)err; (void)fmt;
}
'''


def _httpd_brigade_c() -> str:
    walk = ['    if (node == sentinel) return APR_BRIGADE_LAST(b) == sentinel;']
    for _ in range(8):
        walk.append('    if (!node || !node->link.prev || !node->link.next) return 0;')
        walk.append('    if (node->link.prev->link.next != node || node->link.next->link.prev != node) return 0;')
        walk.append('    node = node->link.next;')
        walk.append('    if (node == sentinel) return 1;')
    frees = ['    e = APR_BRIGADE_FIRST(b);']
    for _ in range(8):
        frees.append('    if (e != APR_BRIGADE_SENTINEL(b)) { next = e->link.next; __vg_release_live(e); e = next; }')
    return '''static apr_bucket_brigade *__vg_brigade_last;
static char __vg_pool_token[8];

static _Bool __vg_brigade_consistent(apr_bucket_brigade *b) {
    apr_bucket *sentinel;
    apr_bucket *node;
    if (!b) return 1;
    sentinel = APR_BRIGADE_SENTINEL(b);
    node = APR_BRIGADE_FIRST(b);
''' + '\n'.join(walk) + '''
    __vg_brigade_truncated = 1;
    return 1;
}

apr_bucket_brigade *__vg_apr_brigade_create(apr_pool_t *p, apr_bucket_alloc_t *list, unsigned callsite) {
    apr_bucket_brigade *b = __vg_apr_palloc(p, sizeof(apr_bucket_brigade), callsite);
    if (!b) return 0;
    memset(b, 0, sizeof(*b));
    b->p = p;
    b->bucket_alloc = list;
    APR_RING_INIT(&b->list, apr_bucket, link);
    __vg_mark_alloc((unsigned char *)b, sizeof(*b), 0);
    __vg_brigade_last = b;
    return b;
}
apr_bucket_brigade *apr_brigade_create(apr_pool_t *p, apr_bucket_alloc_t *list) {
    return __vg_apr_brigade_create(p, list, 0);
}
apr_status_t apr_brigade_destroy(apr_bucket_brigade *b) {
    apr_bucket *e;
    apr_bucket *next;
    if (!b || !__vg_brigade_consistent(b)) return APR_EINVAL;
''' + '\n'.join(frees) + '''
    if (e != APR_BRIGADE_SENTINEL(b)) __vg_brigade_truncated = 1;
    __vg_release_live(b);
    if (__vg_brigade_last == b) __vg_brigade_last = 0;
    return APR_SUCCESS;
}
apr_status_t apr_brigade_cleanup(void *data) {
    return apr_brigade_destroy((apr_bucket_brigade *)data);
}
apr_bucket_alloc_t *apr_bucket_alloc_create(apr_pool_t *p) {
    void *block = __vg_apr_palloc(p, sizeof(void *), 0);
    if (!block) return 0;
    memset(block, 0, sizeof(void *));
    __vg_mark_alloc((unsigned char *)block, sizeof(void *), 0);
    return (apr_bucket_alloc_t *)block;
}
void apr_bucket_alloc_destroy(apr_bucket_alloc_t *list) { __vg_release_live(list); }
void *__vg_apr_bucket_alloc(apr_size_t size, apr_bucket_alloc_t *list, unsigned callsite) {
    (void)list;
    return __vg_heap_alloc((size_t)size, 1, callsite);
}
void *apr_bucket_alloc(apr_size_t size, apr_bucket_alloc_t *list) {
    return __vg_apr_bucket_alloc(size, list, 0);
}
void apr_bucket_free(void *block) { __vg_release_live(block); }
extern _Bool __vulgate_any_blocked;
void __vg_assert_brigade_ring(const void *ptr) {
    if (__vulgate_any_blocked && ptr) {
        __CPROVER_assert(__vg_brigade_consistent((apr_bucket_brigade *)ptr), "vg.obligation.brigade_ring");
    }
}
'''


HTTPD_ENV_MODEL = '''
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_request.h"
#include "http_log.h"
#include "util_filter.h"
#include "apr_strings.h"

void ap_log_rerror_(const char *file, int line, int module_index, int level,
                    apr_status_t status, const request_rec *r, const char *fmt, ...) {
    (void)file; (void)line; (void)module_index; (void)level; (void)status; (void)r; (void)fmt;
}
void ap_log_cerror_(const char *file, int line, int module_index, int level,
                    apr_status_t status, const conn_rec *c, const char *fmt, ...) {
    (void)file; (void)line; (void)module_index; (void)level; (void)status; (void)c; (void)fmt;
}
void ap_log_error_(const char *file, int line, int module_index, int level,
                   apr_status_t status, const server_rec *s, const char *fmt, ...) {
    (void)file; (void)line; (void)module_index; (void)level; (void)status; (void)s; (void)fmt;
}
''' + _allocator_coupling_c() + '''
void *__vg_apr_palloc(apr_pool_t *pool, apr_size_t size, unsigned callsite) {
    if (!pool) return NULL;
    return __vg_heap_alloc((size_t)size, 1, callsite);
}
void *apr_palloc(apr_pool_t *pool, apr_size_t size) { return __vg_apr_palloc(pool, size, 0); }
''' + _httpd_brigade_c()


_SCALAR_WORDS = {
    'int', 'unsigned', 'signed', 'short', 'long', 'char', 'size_t', 'ssize_t',
    'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t', 'int8_t', 'int16_t', 'int32_t', 'int64_t',
    'ngx_int_t', 'ngx_uint_t', 'ngx_flag_t', 'apr_status_t', 'apr_int64_t', 'apr_size_t',
    'off_t', '_Bool', 'bool', 'uintptr_t', 'intptr_t', 'u_char', 'pid_t', 'time_t',
}


def _struct_layouts(source: str) -> dict[str, list[tuple[str, str]]]:
    layouts: dict[str, list[tuple[str, str]]] = {}
    for match in re.finditer(r'typedef\s+struct\s+\w*\s*\{([^{}]*)\}\s*([A-Za-z_]\w*)\s*;', source, re.S):
        fields: list[tuple[str, str]] = []
        for raw in match.group(1).split(';'):
            decl = ' '.join(raw.split())
            if not decl or '*' in decl or '(' in decl or ':' in decl:
                continue
            name = re.search(r'([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*$', decl)
            if not name:
                continue
            prefix = decl[:name.start()].strip().split()
            if not prefix or prefix[-1] not in _SCALAR_WORDS:
                continue
            kind = 'array' if name.group(2) else 'scalar'
            fields.append((name.group(1), kind))
        layouts[match.group(2)] = fields
    return layouts


def _local_is_scalar(body: str, name: str) -> bool:
    for line in body.split(';'):
        if not re.search(rf'\b{re.escape(name)}\b', line):
            continue
        head = line.split(name)[0]
        if '*' in head:
            return False
        return any(word in _SCALAR_WORDS for word in head.replace(',', ' ').split())
    return False


def _impact_span(source: str) -> tuple[int, int] | None:
    match = re.search(r'\bvoid\s+__vg_impact_harness\s*\([^;{]*\)\s*\{', source)
    if not match:
        return None
    start = match.end() - 1
    depth = 0
    for pos in range(start, len(source)):
        if source[pos] == '{':
            depth += 1
        elif source[pos] == '}':
            depth -= 1
            if depth == 0:
                return start, pos + 1
    return None


def complete_observable_diff(source: str) -> str:
    span = _impact_span(source)
    if span is None:
        return source
    body = source[span[0]:span[1]]
    assignment = re.search(r'(_Bool\s+__vg_obs_diff\s*=\s*)([^;]+)(;)', body)
    if not assignment:
        return source
    expr = assignment.group(2).strip()
    terms = [expr]
    layouts = _struct_layouts(source)
    for type_name, fields in layouts.items():
        declared = re.findall(rf'\b{re.escape(type_name)}\s+([^;]+);', body)
        names: list[str] = []
        for group in declared:
            for piece in group.split(','):
                ident = re.match(r'\s*([A-Za-z_]\w*)', piece)
                if ident:
                    names.append(ident.group(1))
        paired = {name[:-1] for name in names if name.endswith('0') and name[:-1] + '1' in names}
        for stem in sorted(paired):
            for field, kind in fields:
                left = f'{stem}0.{field}'
                if re.search(rf'(?<![\w]){re.escape(left)}(?![\w])', expr):
                    continue
                if kind == 'array':
                    terms.append(f'(memcmp({left}, {stem}1.{field}, sizeof({left})) != 0)')
                else:
                    terms.append(f'({left} != {stem}1.{field})')
    for match in re.finditer(r'\b([A-Za-z_]\w*0)\s*=\s*__vg_run_world_0\s*\(', body):
        stem = match.group(1)[:-1]
        right = f'{stem}1 = __vg_run_world_1'
        token = f'{stem}0 != {stem}1'
        if right.replace(' ', '') in body.replace(' ', '') and token not in expr:
            terms.append(f'({stem}0 != {stem}1)')
    for match in re.finditer(r'__vg_run_world_0\s*\(([^;]*)\)', body):
        args = match.group(1)
        for addr in re.findall(r'&([A-Za-z_]\w*0)\b', args):
            stem = addr[:-1]
            if f'&{stem}1' not in body or f'{stem}0' in expr or not _local_is_scalar(body, stem + '0'):
                continue
            terms.append(f'({stem}0 != {stem}1)')
    if len(terms) == 1:
        return source
    replacement = assignment.group(1) + ' || '.join(terms) + assignment.group(3)
    body = body[:assignment.start()] + replacement + body[assignment.end():]
    return source[:span[0]] + body + source[span[1]:]


def mark_parameter_environment(body: str) -> str:
    kept: list[str] = []
    for line in body.splitlines():
        kept.append(line)
        match = re.search(
            r'memset\(\s*(&)?([A-Za-z_][A-Za-z0-9_]*)\s*,\s*0\s*,\s*sizeof\(\s*\2\s*\)\s*\)',
            line,
        )
        if match and match.group(2).endswith('_obj'):
            name = match.group(2)
            address = f'&{name}' if match.group(1) else name
            indent = line[:len(line) - len(line.lstrip())]
            kept.append(
                f'{indent}__vg_mark_alloc((unsigned char *)({address}), sizeof({name}), 1);'
            )
            continue
        assigned = re.match(r'(\s*)([A-Za-z_][A-Za-z0-9_]*_obj)\s*=\s*0\s*;\s*$', line)
        if assigned:
            name = assigned.group(2)
            kept.append(
                f'{assigned.group(1)}__vg_mark_alloc((unsigned char *)(&{name}), sizeof({name}), 1);'
            )
    return '\n'.join(kept) + ('\n' if body.endswith('\n') else '')


def synthesize_paired_goto_driver_c(case_ir: dict[str, Any],
                                    cut_task: dict[str, Any],
                                    abstract_snapshot: dict[str, Any],
                                    output_c_path: Path) -> dict[str, Any]:
    app_family = case_ir['app_profile']['family']
    cut_fn = cut_task['base_name']
    oracle = case_ir['safety_oracle']
    sym_scope = case_ir.get('symbolization_scope', {})
    guards = case_ir['guards']
    guard_fn = guards[0]['function']

    headers: list[str] = []
    if app_family == 'nginx':
        headers.extend([
            '#include <ngx_config.h>',
            '#include <ngx_core.h>',
            '#include <ngx_http.h>',
        ])
    else:
        headers.extend([
            '#include <stdint.h>',
            '#include <stddef.h>',
            '#include <string.h>',
        ])
    headers.extend([
        'extern _Bool __vulgate_any_blocked;',
        'extern _Bool __vulgate_action_write_ok;',
        '_Bool __vulgate_missing_callee_hit;',
        'extern uint64_t __vulgate_nondet_u64(void);',
        'extern uint8_t __vulgate_nondet_u8(void);',
        'extern _Bool __vulgate_nondet_bool(void);',
    ])

    for inc in sym_scope.get('driver_includes', []):
        headers.append(f'#include {inc}')
    helper_includes = (
        ((case_ir.get('app_profile') or {}).get('symbolic_slice') or {}).get('helper_includes')
        or []
    )
    for inc in [*helper_includes, *(sym_scope.get('helper_includes') or [])]:
        text = str(inc).strip()
        if not text:
            continue
        if text.startswith('#'):
            line = text
        elif text[0] in '<"':
            line = f'#include {text}'
        else:
            line = f'#include "{text}"'
        if line not in headers:
            headers.append(line)

    body_c = mark_parameter_environment(_generate_cut_driver_body(
        app_family, case_ir, cut_fn, guard_fn, oracle, sym_scope, abstract_snapshot,
    ))
    if '__vg_alloc_enter_world' not in body_c:
        slice_texts: list[str] = []
        for raw_path in sym_scope.get('slice_sources') or []:
            try:
                slice_texts.append(Path(str(raw_path)).read_text(encoding='utf-8', errors='replace'))
            except OSError:
                continue
        model = allocator_model_for(app_family, slice_texts)
        if model:
            body_c = model + '\n' + body_c
    if '__vg_mark_alloc(' in body_c and 'void __vg_mark_alloc(' not in body_c:
        body_c = (
            'extern _Bool __vulgate_shadow_active;\n'
            'static void __vg_mark_alloc(unsigned char *base, size_t size, _Bool dirty) {\n'
            '    size_t __vg_mark_index;\n'
            '    if (!__vulgate_shadow_active || !base) return;\n'
            '    __CPROVER_assume(size <= 8192u);\n'
            '    for (__vg_mark_index = 0; __vg_mark_index < size; ++__vg_mark_index)\n'
            '        __CPROVER_set_field(base + __vg_mark_index, "vulgate_uninitialized", dirty);\n'
            '}\n\n' + body_c
        )
    profile = case_ir.get('app_profile') or {}
    include_dirs = [
        str(item)
        for item in [
            *((profile.get('symbolic_slice') or {}).get('include_dirs') or []),
            *(((profile.get('builds') or {}).get('baseline') or {}).get('include_dirs') or []),
            *((case_ir.get('symbolization_scope') or {}).get('include_dirs') or []),
        ]
    ]
    body_c = apply_oracle_assertions(
        body_c,
        oracle,
        sym_scope.get('cut_harness_kind'),
        included_layout_text(body_c, include_dirs),
    )
    body_c = inject_poc_baseline_nonvacuity(body_c, case_ir)
    body_c = apply_snapshot_seed(
        body_c,
        abstract_snapshot,
        defer_episode_steps=episode_count(case_ir) >= 2,
    )
    body_c = inject_initial_map_state(body_c, case_ir)
    body_c = apply_snapshot_state(body_c, abstract_snapshot)
    body_c = apply_episode_driver(body_c, case_ir, abstract_snapshot)
    body_c = inject_missing_callee_assert(body_c)
    body_c = inject_allocator_obligations(body_c)
    full_c = inject_resource_balance(inject_benign_impact_domain(
        complete_observable_diff('\n'.join(headers) + '\n\n' + body_c + '\n'),
        case_ir,
    ))
    output_c_path.parent.mkdir(parents=True, exist_ok=True)
    output_c_path.write_text(full_c, encoding='utf-8')
    return {
        'driver_path': str(output_c_path),
        'cut_function': cut_fn,
        'app_family': app_family,
        'oracle_kind': oracle.get('kind'),
    }


_PROTO_INTEGER_WORDS = {
    'int', 'unsigned', 'signed', 'long', 'short', 'char', 'void',
    'size_t', 'ssize_t', 'ptrdiff_t', 'uintptr_t', 'intptr_t', 'uint64_t', 'uint32_t',
    'uint16_t', 'uint8_t', 'int64_t', 'int32_t', 'int16_t', 'int8_t',
    'ngx_int_t', 'ngx_uint_t', 'ngx_flag_t', 'apr_status_t', 'apr_size_t',
    'apr_off_t', 'off_t', 'pid_t', 'time_t', 'zend_long', 'zend_ulong', 'zend_result',
    'float', 'double', '_Bool', 'bool', 'u_char', 'u_short', 'u_int', 'u_long',
}


def _proto_skip_string(text: str, index: int) -> int:
    quote = text[index]
    index += 1
    while index < len(text):
        if text[index] == '\\':
            index += 2
            continue
        if text[index] == quote:
            return index + 1
        index += 1
    return index


def _proto_match(text: str, open_at: int, open_ch: str, close_ch: str) -> int:
    depth = 0
    index = open_at
    while index < len(text):
        if text[index] in '"\'':
            index = _proto_skip_string(text, index)
            continue
        if text[index] == open_ch:
            depth += 1
        elif text[index] == close_ch:
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def _preprocessor_line_end(text: str, index: int) -> int:
    while index < len(text):
        line_end = text.find('\n', index)
        if line_end < 0:
            return len(text)
        probe = line_end - 1
        while probe > index and text[probe] in ' \t\r':
            probe -= 1
        if probe >= index and text[probe] == '\\':
            index = line_end + 1
            continue
        return line_end
    return index


def _match_code_brace(text: str, open_at: int) -> int:
    depth = 0
    index = open_at
    frames: list[dict[str, bool]] = []
    while index < len(text):
        if text[index] in '"\'':
            index = _proto_skip_string(text, index)
            continue
        if text[index] == '#' and (index == 0 or text[index - 1] == '\n'):
            newline = text.find('\n', index)
            first = text[index + 1:] if newline < 0 else text[index + 1:newline]
            first = first.split('\\', 1)[0]
            words = first.strip().split(None, 1)
            directive = words[0] if words else ''
            condition = words[1].strip() if len(words) > 1 else ''
            if directive in {'if', 'ifdef', 'ifndef'}:
                parent = all(frame['emit'] for frame in frames)
                if not parent:
                    frames.append({'emit': False, 'else_emit': False})
                elif directive == 'if' and condition == '0':
                    frames.append({'emit': False, 'else_emit': True})
                else:
                    frames.append({'emit': True, 'else_emit': False})
            elif directive in {'else', 'elif'} and frames:
                frames[-1]['emit'] = frames[-1]['else_emit']
                frames[-1]['else_emit'] = False
            elif directive == 'endif' and frames:
                frames.pop()
            index = _preprocessor_line_end(text, index)
            continue
        if all(frame['emit'] for frame in frames):
            if text[index] == '{':
                depth += 1
            elif text[index] == '}':
                depth -= 1
                if depth == 0:
                    return index
        index += 1
    return -1


def _strip_c_comments(source: str) -> str:
    out: list[str] = []
    index = 0
    while index < len(source):
        if source.startswith('//', index):
            newline = source.find('\n', index)
            index = len(source) if newline < 0 else newline
            continue
        if source.startswith('/*', index):
            end = source.find('*/', index + 2)
            index = len(source) if end < 0 else end + 2
            continue
        if source[index] in '"\'':
            end = _proto_skip_string(source, index)
            out.append(source[index:end])
            index = end
            continue
        out.append(source[index])
        index += 1
    return ''.join(out)


def _type_keyword_before_brace(text: str, close_at: int) -> int:
    window_at = max(0, close_at - 4000)
    window = text[window_at:close_at]
    for kind in ('struct', 'union', 'enum'):
        for match in re.finditer(rf'(?<![\w]){kind}\s*\{{', window):
            open_at = window_at + match.end() - 1
            if _proto_match(text, open_at, '{', '}') == close_at:
                return window_at + match.start()
    return -1


def _header_start(text: str, index: int) -> int:
    depth = 0
    cursor = index - 1
    while cursor >= 0:
        char = text[cursor]
        if char == ')' and depth == 0:
            open_at = _match_paren_back(text, cursor)
            if open_at >= 0:
                token_at = open_at - 1
                while token_at >= 0 and text[token_at].isspace():
                    token_at -= 1
                token_end = token_at + 1
                while token_at >= 0 and (text[token_at].isalnum() or text[token_at] == '_'):
                    token_at -= 1
                token = text[token_at + 1:token_end]
                if token and token not in {'__attribute__', '__declspec', '__attribute'}:
                    if _decl_macro_name(token) and text[cursor + 1:index].strip() == '':
                        cursor = token_at
                        continue
                    return cursor + 1
        if char == '}' and depth == 0:
            probe = cursor + 1
            while probe < len(text) and text[probe].isspace():
                probe += 1
            keyword_at = _type_keyword_before_brace(text, cursor) if probe >= len(text) or text[probe] != ';' else -1
            if keyword_at >= 0:
                cursor = keyword_at - 1
                continue
            return cursor + 1
        if char in ')]}':
            depth += 1
        elif char in '([{':
            if depth == 0:
                return cursor + 1
            depth -= 1
        elif char == ';' and depth == 0:
            return cursor + 1
        cursor -= 1
    return 0


def _split_signature_params(text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    depth = 0
    index = 0
    while index < len(text):
        if text[index] in '"\'':
            index = _proto_skip_string(text, index)
            continue
        if text[index] in '([{':
            depth += 1
        elif text[index] in ')]}':
            depth = max(0, depth - 1)
        elif text[index] == ',' and depth == 0:
            parts.append(text[start:index].strip())
            start = index + 1
        index += 1
    tail = text[start:].strip()
    if tail:
        parts.append(tail)
    return parts


def _typedef_bodies(source: str) -> list[tuple[str, str]]:
    text = _strip_c_comments(source)
    found: list[tuple[str, str]] = []
    start_at = 0
    while start_at < len(text):
        match = re.search(r'(?<![\w])typedef\b', text[start_at:])
        if match is None:
            break
        start = start_at + match.start()
        depth = 0
        index = start
        end = -1
        while index < len(text):
            if text[index] in '"\'':
                index = _proto_skip_string(text, index)
                continue
            char = text[index]
            if char == '{':
                depth += 1
            elif char == '}':
                depth = max(0, depth - 1)
            elif char == ';' and depth == 0:
                end = index
                break
            index += 1
        if end < 0:
            break
        body = text[start:end + 1].strip()
        pointed = re.search(
            r'\(\s*\*(?:\s*const\s*)?\s*([A-Za-z_]\w*)\s*\)\s*\(',
            ' '.join(body.split()),
        )
        words = re.findall(r'[A-Za-z_]\w*', body)
        name = pointed.group(1) if pointed else (words[-1] if words else '')
        if name and name != 'typedef':
            found.append((name, body))
        start_at = end + 1
    return found


def _signature_type_names(signature: dict[str, Any]) -> list[str]:
    blobs = [str(signature.get('return_type') or '')]
    for item in signature.get('parameters') or []:
        blobs.append(str(item.get('type_text') or ''))
        blobs.append(str(item.get('pointee') or ''))
        blobs.append(str(item.get('args_text') or ''))
    names: list[str] = []
    for blob in blobs:
        for word in re.findall(r'[A-Za-z_]\w*', blob):
            if word in _PROTO_INTEGER_WORDS or word in {'struct', 'union', 'enum'} or word in names:
                continue
            names.append(word)
    return names


def _tag_bodies(source: str) -> list[tuple[str, str]]:
    text = _strip_c_comments(source)
    found: list[tuple[str, str]] = []
    for match in re.finditer(r'(?<![\w])(?:struct|union|enum)\s+([A-Za-z_]\w*)\s*\{', text):
        end = _balanced_decl(text, match.end() - 1)
        if end is None:
            continue
        found.append((match.group(1), text[match.start():end + 1].strip()))
    return found


def _balanced_decl(text: str, open_at: int) -> int | None:
    depth = 0
    index = open_at
    while index < len(text):
        if text[index] in '"\'':
            index = _proto_skip_string(text, index)
            continue
        char = text[index]
        if char == '{':
            depth += 1
        elif char == '}':
            depth -= 1
            if depth == 0:
                end = text.find(';', index)
                return None if end < 0 else end
        index += 1
    return None


def _needed_typedef_bodies(source: str, names: list[str]) -> list[str]:
    by_name: dict[str, list[str]] = {}
    for name, body in [*_typedef_bodies(source), *_tag_bodies(source)]:
        bodies = by_name.setdefault(name, [])
        if body not in bodies:
            bodies.append(body)
    ordered: list[str] = []
    seen: set[str] = set()

    def walk(name: str) -> None:
        for body in by_name.get(name, []):
            if body in seen:
                continue
            seen.add(body)
            for word in re.findall(r'[A-Za-z_]\w*', body):
                if word != name and word in by_name:
                    walk(word)
            ordered.append(body)

    for name in names:
        walk(name)
    return ordered


def _with_local_typedefs(source: str, signature: dict[str, Any]) -> dict[str, Any]:
    bound = dict(signature)
    invented = [
        str(item.get('definition') or '')
        for item in signature.get('anonymous_types') or []
        if str(item.get('definition') or '')
    ]
    bound['local_typedef_bodies'] = invented + _needed_typedef_bodies(source, _signature_type_names(signature))
    return bound


def _merged_typedef_text(signatures: list[dict[str, Any]]) -> str:
    bodies: list[str] = []
    seen: set[str] = set()
    for signature in signatures:
        for body in signature.get('local_typedef_bodies') or []:
            if body in seen:
                continue
            seen.add(body)
            bodies.append(body)
    if not bodies:
        return ''
    return '\n'.join(bodies) + '\n'


def _drop_calling_convention(text: str) -> str:
    return re.sub(
        r'\b[A-Za-z_][A-Za-z0-9_]*(?:inline|cdecl|stdcall|fastcall)\b',
        ' ',
        text,
        flags=re.IGNORECASE,
    )


def _clean_type_text(text: str) -> str:
    cleaned = re.sub(
        r'\b(?:static|inline|extern|_Noreturn|__inline|__inline__|const|volatile|restrict|register)\b',
        ' ',
        text,
    )
    cleaned = re.sub(r'\b[A-Za-z_][A-Za-z0-9_]*INLINE\b', ' ', cleaned)
    cleaned = _drop_calling_convention(cleaned)
    return _drop_leading_caps(_drop_export_macros(cleaned))


def _callback_record(ret: str, name: str, args: str, index: int) -> dict[str, Any] | None:
    cleaned = ' '.join(_clean_type_text(ret).split())
    if not cleaned or name in _PROTO_INTEGER_WORDS or name in {'struct', 'union', 'enum'}:
        return None
    if not re.fullmatch(
        r'(?:(?:const|struct|union|enum|unsigned|signed|long|short|int|char|void)\s+)*[A-Za-z_]\w*(?:\s*\*)*',
        cleaned,
    ):
        return None
    shown = ' '.join(args.split()) or 'void'
    if not _callback_args_accepted(shown):
        return None
    words = cleaned.split()
    return {
        'kind': 'function_pointer',
        'name': name,
        'type_text': cleaned,
        'decl_type': f'{cleaned} (*{name})({shown})',
        'pointee': cleaned,
        'args_text': shown,
        'array_len': None,
        'index': index,
        'returns_aggregate': bool(words) and words[0] in {'struct', 'union'} and '*' not in cleaned,
    }


def _array_of_callbacks(text: str, index: int) -> dict[str, Any] | None:
    raw = ' '.join(text.split())
    match = re.match(
        r'(?P<type>.+?)\s*\(\s*\*\s*(?P<name>[A-Za-z_]\w*)\s*(?P<dims>(?:\[\s*\d*\s*\])+)\s*\)\s*\(',
        raw,
    )
    if match is None:
        return None
    name = match.group('name')
    if name in _PROTO_INTEGER_WORDS or name in {'struct', 'union', 'enum'}:
        return None
    dims: list[int] = []
    for dim in re.finditer(r'\[\s*(\d*)\s*\]', match.group('dims')):
        length = dim.group(1)
        size = int(length) if length else 16
        dims.append(size if size > 0 else 16)
    if not dims:
        return None
    args_open = match.end() - 1
    args_close = _proto_match(raw, args_open, '(', ')')
    if args_close < 0 or args_close + 1 != len(raw):
        return None
    args = ' '.join(raw[args_open + 1:args_close].split()) or 'void'
    if not _callback_args_accepted(args):
        return None
    cleaned = ' '.join(_clean_type_text(match.group('type')).split())
    if not cleaned or any(char in cleaned for char in '()[]'):
        return None
    if not re.fullmatch(
        r'(?:(?:const|struct|union|enum|unsigned|signed|long|short|int|char|void)\s+)*[A-Za-z_]\w*(?:\s*\*)*',
        cleaned,
    ):
        return None
    shown = ''.join(f'[{size}]' for size in dims)
    return {
        'kind': 'function_pointer',
        'name': name,
        'type_text': cleaned,
        'decl_type': f'{cleaned} (*{name}{shown})({args})',
        'pointee': cleaned,
        'args_text': args,
        'array_len': None,
        'index': index,
        'returns_aggregate': False,
        'callback_array_dims': dims,
    }


def _wrap_callback_core(ret: str, core: str, layers: list[str], suffix: str) -> str:
    text = core
    for mid in layers:
        text = f'(*{text})({mid})'
    return f'{ret} (*{text}){suffix}'


def _deeper_callback_param(text: str, index: int) -> dict[str, Any] | None:
    raw = ' '.join(text.split())
    match = re.match(
        r'(?P<type>.+?)\s*(?P<opens>(?:\(\s*\*\s*){3,9})(?P<name>[A-Za-z_]\w*)\s*\)\s*\(',
        raw,
    )
    if match is None:
        return None
    name = match.group('name')
    if name in _PROTO_INTEGER_WORDS or name in {'struct', 'union', 'enum'}:
        return None
    if any(char in match.group('type') for char in '()[]'):
        return None
    cleaned = ' '.join(_clean_type_text(match.group('type')).split())
    if not cleaned or not re.fullmatch(
        r'(?:(?:const|struct|union|enum|unsigned|signed|long|short|int|char|void)\s+)*[A-Za-z_]\w*(?:\s*\*)*',
        cleaned,
    ):
        return None
    opens = len(re.findall(r'\(\s*\*', match.group('opens')))
    args_open = match.end() - 1
    args_close = _proto_match(raw, args_open, '(', ')')
    if args_close < 0:
        return None
    args = ' '.join(raw[args_open + 1:args_close].split()) or 'void'
    if not _callback_args_accepted(args):
        return None
    layers: list[str] = []
    cursor = args_close + 1
    for _layer in range(opens - 2):
        cursor = _skip_sig_space(raw, cursor)
        if cursor >= len(raw) or raw[cursor] != ')':
            return None
        cursor = _skip_sig_space(raw, cursor + 1)
        if cursor >= len(raw) or raw[cursor] != '(':
            return None
        mid_close = _proto_match(raw, cursor, '(', ')')
        if mid_close < 0:
            return None
        mid_args = ' '.join(raw[cursor + 1:mid_close].split()) or 'void'
        if not _callback_args_accepted(mid_args):
            return None
        layers.append(mid_args)
        cursor = mid_close + 1
    cursor = _skip_sig_space(raw, cursor)
    if cursor >= len(raw) or raw[cursor] != ')':
        return None
    cursor = _skip_sig_space(raw, cursor + 1)
    mid_args = layers[0]
    dims: list[int] | None = None
    outer_args = ''
    parsed_dims = _read_array_dims(raw, cursor)
    if parsed_dims is not None:
        dims, end = parsed_dims
        if end != len(raw):
            return None
    else:
        parsed_callback = _read_callback_suffix(raw, cursor)
        if parsed_callback is None:
            return None
        outer_args, end = parsed_callback
        if end != len(raw) or not _callback_args_accepted(outer_args):
            return None
    suffix = ''.join(f'[{size}]' for size in dims) if dims else f'({outer_args})'
    decl = _wrap_callback_core(cleaned, f'(*{name})({args})', layers, suffix)
    return {
        'kind': 'function_pointer',
        'name': name,
        'type_text': cleaned,
        'decl_type': decl,
        'pointee': cleaned,
        'args_text': args,
        'array_len': None,
        'index': index,
        'returns_aggregate': False,
        'callback_stars': '*',
        'callback_mid_args': mid_args,
        'callback_layer_args': layers,
        'callback_return_stars': '*',
        'callback_return_dims': dims,
        'callback_return_args': outer_args,
    }


def _nested_callback_param(text: str, index: int) -> dict[str, Any] | None:
    raw = ' '.join(text.split())
    match = re.match(
        r'(?P<type>.+?)\s*\(\s*\*\s*\(\s*(?P<stars>\*+(?:\s*(?:const|volatile|restrict)\s*)*)\s*(?P<name>[A-Za-z_]\w*)\s*\)\s*\(',
        raw,
    )
    if match is None:
        return None
    name = match.group('name')
    if name in _PROTO_INTEGER_WORDS or name in {'struct', 'union', 'enum'}:
        return None
    stars = ' '.join(match.group('stars').split())
    if stars.count('*') < 1 or stars.count('*') > 2:
        return None
    args_open = match.end() - 1
    args_close = _proto_match(raw, args_open, '(', ')')
    if args_close < 0:
        return None
    args = ' '.join(raw[args_open + 1:args_close].split()) or 'void'
    if not _callback_args_accepted(args):
        return None
    cursor = args_close + 1
    while cursor < len(raw) and raw[cursor].isspace():
        cursor += 1
    if cursor >= len(raw) or raw[cursor] != ')':
        return None
    cursor += 1
    parsed_dims = _read_array_dims(raw, cursor)
    callback_args = ''
    dims: list[int] | None = None
    if parsed_dims is not None:
        dims, end = parsed_dims
        if end != len(raw):
            return None
    else:
        parsed_callback = _read_callback_suffix(raw, cursor)
        if parsed_callback is None:
            return None
        callback_args, end = parsed_callback
        if end != len(raw):
            return None
    cleaned = ' '.join(_clean_type_text(match.group('type')).split())
    if not cleaned or any(char in cleaned for char in '()[]'):
        return None
    if not re.fullmatch(
        r'(?:(?:const|struct|union|enum|unsigned|signed|long|short|int|char|void)\s+)*[A-Za-z_]\w*(?:\s*\*)*',
        cleaned,
    ):
        return None
    joiner = '' if stars.endswith('*') else ' '
    suffix = ''.join(f'[{size}]' for size in dims) if dims else f'({callback_args})'
    return {
        'kind': 'function_pointer',
        'name': name,
        'type_text': cleaned,
        'decl_type': f'{cleaned} (*({stars}{joiner}{name})({args})){suffix}',
        'pointee': cleaned,
        'args_text': args,
        'array_len': None,
        'index': index,
        'returns_aggregate': False,
        'callback_stars': stars,
        'callback_return_stars': '*',
        'callback_return_dims': dims,
        'callback_return_args': callback_args,
    }


def _function_pointer_param(text: str, index: int) -> dict[str, Any] | None:
    match = re.fullmatch(
        r'(?P<ret>.+?)\s*\(\s*(?:(?:const|volatile|restrict)\s+)*\*\s*(?:(?:const|volatile|restrict)\s+)*(?P<name>[A-Za-z_]\w*)\s*\)\s*\((?P<args>.*)\)',
        text.strip(),
    )
    if match is None:
        return None
    return _callback_record(match.group('ret'), match.group('name'), match.group('args'), index)


def _function_declarator_param(text: str, index: int) -> dict[str, Any] | None:
    match = re.fullmatch(
        r'(?P<ret>.+?)\s+(?P<name>[A-Za-z_]\w*)\s*\((?P<args>.*)\)',
        text.strip(),
    )
    if match is None:
        return None
    return _callback_record(match.group('ret'), match.group('name'), match.group('args'), index)


def _skip_sig_space(text: str, index: int) -> int:
    while index < len(text) and text[index].isspace():
        index += 1
    return index


def _simplify_param_parens_once(text: str) -> str | None:
    index = 0
    while index < len(text):
        if text[index] in '"\'':
            index = _proto_skip_string(text, index)
            continue
        if text[index] != '(':
            index += 1
            continue
        close = _proto_match(text, index, '(', ')')
        if close < 0:
            return None
        content = text[index + 1:close].strip()
        after = _skip_sig_space(text, close + 1)
        nxt = text[after] if after < len(text) else ''
        ident = re.fullmatch(r'[A-Za-z_]\w*', content)
        if ident and ident.group(0) not in _PROTO_INTEGER_WORDS and ident.group(0) not in {'struct', 'union', 'enum'}:
            return text[:index] + content + text[close + 1:]
        starred = re.fullmatch(r'(?:\*|const|volatile|restrict|\s)+[A-Za-z_]\w*', content)
        if starred and nxt not in '([':
            return text[:index] + ' '.join(content.split()) + text[close + 1:]
        if after >= len(text) and _declarator_type_prefix(text[:index], content):
            return text[:index].strip() + ' ' + content
        index += 1
    return None


def _declarator_type_prefix(prefix: str, content: str) -> bool:
    text = prefix.strip()
    if not text or any(char in text for char in '()[]'):
        return False
    words = text.split()
    if words[-1] in _PROTO_INTEGER_WORDS or text.endswith('*'):
        return True
    if len(words) >= 2 and words[-2] in {'struct', 'union', 'enum'}:
        return True
    if all(word in _PROTO_INTEGER_WORDS or word in {'const', 'volatile', 'restrict'} for word in words):
        return True
    body = content.lstrip()
    return len(words) == 1 and body.startswith(('(', '*'))


def _simplify_param_parens(text: str) -> str:
    current = ' '.join(text.replace('\n', ' ').split())
    for _pass in range(8):
        updated = _simplify_param_parens_once(current)
        if updated is None:
            return current
        updated = ' '.join(updated.split())
        if updated == current:
            return current
        current = updated
    return current


def _callback_args_accepted(args: str) -> bool:
    text = ' '.join(args.split()) or 'void'
    if text == 'void':
        return True
    for part in _split_signature_params(text):
        if not part or part == '...' or any(char in part for char in '{};'):
            return False
        shown = _simplify_param_parens(part)
        if (
            _array_of_callbacks(shown, 0) is not None
            or _nested_callback_param(shown, 0) is not None
            or _deeper_callback_param(shown, 0) is not None
            or _function_pointer_param(shown, 0) is not None
            or _function_declarator_param(shown, 0) is not None
            or _pointer_to_array_param(shown, 0) is not None
        ):
            continue
        if '(' in shown or ')' in shown:
            return False
    return True


def _trailing_array_bound(text: str) -> tuple[str, int] | None:
    raw = text.rstrip()
    if not raw.endswith(']'):
        return None
    depth = 0
    index = len(raw) - 1
    while index >= 0:
        char = raw[index]
        if char == ']':
            depth += 1
        elif char == '[':
            depth -= 1
            if depth == 0:
                return raw[:index].rstrip(), 16
        index -= 1
    return None


def _parse_signature_param(raw: str, index: int) -> dict[str, Any] | None:
    text = _unwrap_decl_macros(raw)
    parsed = _parse_param_text(text, index)
    if parsed is not None:
        return parsed
    simplified = _simplify_param_parens(text)
    if simplified == text:
        return None
    return _parse_param_text(simplified, index)


def _parse_param_text(text: str, index: int) -> dict[str, Any] | None:
    if text == 'void':
        return {'kind': 'void'}
    if text in ('', '...'):
        return None
    function_pointer = (
        _array_of_callbacks(text, index)
        or _nested_callback_param(text, index)
        or _deeper_callback_param(text, index)
        or _function_pointer_param(text, index)
        or _function_declarator_param(text, index)
    )
    if function_pointer is not None:
        return function_pointer
    array_pointer = _pointer_to_array_param(text, index)
    if array_pointer is not None:
        return array_pointer
    array_len = None
    if not re.search(r'\[\s*\d*\s*\]\s*$', text):
        bound = _trailing_array_bound(text)
        if bound is not None:
            text, array_len = bound
    if '(' in text or ')' in text:
        return None
    array = re.search(r'\[\s*(\d*)\s*\]\s*$', text)
    if array:
        length = array.group(1)
        array_len = int(length) if length else 16
        if array_len <= 0:
            array_len = 16
        text = text[:array.start()].strip()
    name_match = re.search(r'([A-Za-z_]\w*)\s*$', text)
    if name_match is None:
        return None
    name = name_match.group(1)
    decl_type = _decl_type_text(text[:name_match.start()])
    type_text = _clean_type_text(text[:name_match.start()])
    if not type_text or name in _PROTO_INTEGER_WORDS or name in {'struct', 'union', 'enum'}:
        return None
    pointer = '*' in type_text or array_len is not None
    pointee = ' '.join(type_text.replace('*', ' ').split())
    words = pointee.split()
    integer = (not pointer) and bool(words) and all(
        _is_scalar_word(word) for word in words
    ) and words[-1] != 'void'
    kind = 'integer' if integer else 'pointer'
    if not pointer and words[:1] == ['struct'] or (not pointer and words[:1] == ['union']):
        kind = 'struct_value'
    if not pointer and words[:1] == ['enum'] and len(words) == 2:
        kind = 'integer'
    if pointer and (pointee == 'void' or array_len is not None):
        kind = 'buffer'
    if kind == 'pointer' and not pointer:
        if len(words) == 1:
            kind = 'struct_value'
        else:
            return None
    return {
        'kind': kind,
        'name': name,
        'type_text': type_text if array_len is None else pointee,
        'decl_type': decl_type if array_len is None else pointee,
        'pointee': pointee,
        'array_len': array_len,
        'index': index,
    }


def _anonymous_spans(text: str) -> list[tuple[int, int, str]]:
    spans: list[tuple[int, int, str]] = []
    index = 0
    while index < len(text):
        if text[index] in '"\'':
            index = _proto_skip_string(text, index)
            continue
        if text[index] == '{':
            kind_match = re.search(r'(struct|union|enum)\s*$', text[:index])
            if kind_match:
                end = _proto_match(text, index, '{', '}')
                if end < 0:
                    break
                spans.append((kind_match.start(1), end + 1, kind_match.group(1)))
                index = end + 1
                continue
        index += 1
    return spans


def _lift_anonymous_types(fragment: str, function: str, role: str, found: list[dict[str, str]]) -> str:
    while True:
        spans = _anonymous_spans(fragment)
        if not spans:
            return fragment
        start, end, kind = spans[0]
        spelling = fragment[start:end]
        normalized = ' '.join(spelling.split())
        prior = next((item for item in found if item.get('normalized') == normalized), None)
        if prior is None:
            tag = f'__vg_anon_{function}_{role}_{len(found)}'
            brace = spelling[spelling.find('{'):]
            prior = {
                'normalized': normalized,
                'tag': tag,
                'kind': kind,
                'definition': f'{kind} {tag} {brace};',
            }
            found.append(prior)
        fragment = fragment[:start] + f'{kind} {prior["tag"]}' + fragment[end:]


def _function_regions(source: str, function: str) -> list[tuple[int, int]]:
    regions: list[tuple[int, int]] = []
    pattern = re.compile(rf'(?<![\w#]){re.escape(function)}\s*\(')
    for match in pattern.finditer(source):
        close = _proto_match(source, match.end() - 1, '(', ')')
        if close < 0:
            continue
        cursor = close + 1
        while cursor < len(source) and source[cursor].isspace():
            cursor += 1
        header_at = _header_start(source, match.start())
        if cursor < len(source) and source[cursor] == '{':
            body_end = _proto_match(source, cursor, '{', '}')
            if body_end < 0:
                continue
            regions.append((header_at, body_end + 1))
            continue
        regions.append((header_at, close + 1))
    return regions


def align_anonymous_signatures(source: str, signatures: list[dict[str, Any]]) -> str:
    text = source
    inserts: list[tuple[int, str]] = []
    replacements: list[tuple[int, int, str]] = []
    for signature in signatures:
        types = [item for item in (signature.get('anonymous_types') or []) if item.get('normalized') and item.get('tag')]
        if not types:
            continue
        function = str(signature.get('name') or '')
        if not function:
            continue
        regions = _function_regions(text, function)
        if not regions:
            continue
        prelude = '\n'.join(
            str(item['definition'])
            for item in types
            if str(item.get('definition') or '') and str(item['definition']) not in text
        )
        if prelude:
            inserts.append((regions[0][0], prelude + '\n'))
        for start, end in regions:
            for span_start, span_end, kind in _anonymous_spans(text[start:end]):
                absolute_start = start + span_start
                absolute_end = start + span_end
                normalized = ' '.join(text[absolute_start:absolute_end].split())
                matched = next((item for item in types if item['normalized'] == normalized), None)
                if matched is None or matched.get('kind') not in {kind, None}:
                    continue
                replacements.append((absolute_start, absolute_end, f'{kind} {matched["tag"]}'))
    if not replacements and not inserts:
        return text
    pieces: list[tuple[int, int, str]] = [(start, end, replacement) for start, end, replacement in replacements]
    for at, prelude in inserts:
        pieces.append((at, at, prelude))
    pieces.sort(key=lambda item: (item[0], item[1] - item[0]), reverse=True)
    for start, end, replacement in pieces:
        text = text[:start] + replacement + text[end:]
    return text


def _blank_preprocessor(text: str) -> str:
    lines = text.splitlines(keepends=True)
    blanked: list[str] = []
    continued = False
    for line in lines:
        body = line.rstrip('\r\n')
        newline = line[len(body):]
        if continued or body.lstrip().startswith('#'):
            blanked.append(newline)
            continued = body.rstrip().endswith('\\')
            continue
        continued = False
        blanked.append(line)
    return ''.join(blanked)


def _match_paren_back(text: str, close_at: int) -> int:
    depth = 0
    cursor = close_at
    while cursor >= 0:
        char = text[cursor]
        if char == ')':
            depth += 1
        elif char == '(':
            depth -= 1
            if depth == 0:
                return cursor
        cursor -= 1
    return -1


def _read_array_dims(text: str, index: int) -> tuple[list[int], int] | None:
    dims: list[int] = []
    cursor = index
    while cursor < len(text) and text[cursor].isspace():
        cursor += 1
    if cursor >= len(text) or text[cursor] != '[':
        return None
    while cursor < len(text) and text[cursor] == '[':
        end = text.find(']', cursor)
        if end < 0:
            return None
        inner = text[cursor + 1:end].strip()
        size = int(inner) if inner else 16
        dims.append(size if size > 0 else 16)
        cursor = end + 1
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
    return dims, cursor


def _read_callback_suffix(text: str, index: int) -> tuple[str, int] | None:
    cursor = index
    while cursor < len(text) and text[cursor].isspace():
        cursor += 1
    if cursor >= len(text) or text[cursor] != '(':
        return None
    end = _proto_match(text, cursor, '(', ')')
    if end < 0:
        return None
    args = ' '.join(text[cursor + 1:end].split()) or 'void'
    if any(char in args for char in '{};'):
        return None
    cursor = end + 1
    while cursor < len(text) and text[cursor].isspace():
        cursor += 1
    return args, cursor


def parse_c_function_signature(source: str, function: str, include_static: bool = False) -> dict[str, Any] | None:
    text = _blank_preprocessor(_strip_c_comments(_expand_local_decl_macros(source)))
    pattern = re.compile(rf'(?<![\w#]){re.escape(function)}\s*\(')
    for match in pattern.finditer(text):
        close = _proto_match(text, match.end() - 1, '(', ')')
        if close < 0:
            continue
        cursor = close + 1
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        while text.startswith('__attribute__', cursor) or text.startswith('__declspec', cursor):
            paren = text.find('(', cursor)
            if paren < 0:
                cursor = len(text)
                break
            end = _proto_match(text, paren, '(', ')')
            if end < 0:
                cursor = len(text)
                break
            cursor = end + 1
            while cursor < len(text) and text[cursor].isspace():
                cursor += 1
        array_dims: list[int] | None = None
        return_stars = ''
        return_callback = ''
        raw_at = match.start()
        if cursor < len(text) and text[cursor] == ')':
            suffix_cursor = None
            parsed_dims = _read_array_dims(text, cursor + 1)
            if parsed_dims is not None:
                dims, suffix_cursor = parsed_dims
            else:
                parsed_callback = _read_callback_suffix(text, cursor + 1)
                if parsed_callback is not None:
                    return_callback, suffix_cursor = parsed_callback
                    dims = None
            if suffix_cursor is not None and text[suffix_cursor:suffix_cursor + 1] in '{;':
                open_paren = _match_paren_back(text, cursor)
                inner = text[open_paren + 1:match.start()] if open_paren >= 0 else ''
                stars = ' '.join(inner.split())
                if (
                    open_paren >= 0
                    and re.fullmatch(r'(?:\*|const|volatile|restrict|\s)+', stars)
                    and 1 <= stars.count('*') <= 9
                ):
                    if parsed_dims is not None:
                        array_dims = dims
                    return_stars = stars
                    cursor = suffix_cursor
                    raw_at = open_paren
                else:
                    return_callback = ''
        if cursor >= len(text) or text[cursor] not in '{;':
            continue
        raw_header = text[_header_start(text, raw_at):raw_at]
        raw_header = '\n'.join(
            line for line in raw_header.splitlines()
            if not line.strip().startswith('#')
        )
        is_static = bool(re.search(r'\bstatic\b', raw_header))
        if is_static and not include_static:
            continue
        anonymous_types: list[dict[str, str]] = []
        raw_header = _lift_anonymous_types(raw_header, function, 'ret', anonymous_types)
        raw_header = _unwrap_decl_macros(raw_header)
        return_decl = _decl_type_text(raw_header)
        return_type = _clean_type_text(raw_header)
        if not re.fullmatch(
            r'(?:(?:const|struct|union|enum|unsigned|signed|long|short|int|char|void)\s+)*[A-Za-z_]\w*(?:\s*\*)*',
            return_decl,
        ):
            continue
        if array_dims or return_callback:
            return_type = (return_type + ' ' + ('*' * return_stars.count('*'))).strip()
        return_words = return_type.replace('*', ' ').split()
        aggregate_return = (
            bool(return_words)
            and return_words[0] in {'struct', 'union'}
            and '*' not in return_type
        )
        enum_return = len(return_words) == 2 and return_words[0] == 'enum' and '*' not in return_type
        scalar_return = (
            return_type == 'void'
            or '*' in return_type
            or enum_return
            or all(_is_scalar_word(word) for word in return_words)
        )
        named_return = ''
        if (
            len(return_words) == 1
            and '*' not in return_type
            and re.fullmatch(r'[A-Za-z_]\w*', return_words[0])
        ):
            named_return = return_words[0]
        if named_return and _typedef_aggregate(text, named_return):
            aggregate_return = True
            scalar_return = False
        elif not scalar_return and not aggregate_return:
            if named_return:
                scalar_return = True
            else:
                continue
        parsed: list[dict[str, Any]] = []
        failed = False
        variadic = False
        for index, raw in enumerate(_split_signature_params(text[match.end():close])):
            if raw.strip() == '...':
                variadic = True
                continue
            rewritten = _lift_anonymous_types(raw, function, f'p{index}', anonymous_types)
            item = _parse_signature_param(rewritten, index)
            if item is None:
                failed = True
                break
            if item['kind'] != 'void':
                parsed.append(item)
        if failed:
            continue
        if any(item['kind'] == 'void' for item in parsed):
            continue
        aliases = _typedef_alias_map(text)
        ap_map = _fold_alias_map(_array_pointer_typedef_map(text), aliases)
        parsed = _promote_array_pointer_typedefs(parsed, ap_map)
        ap_ret = ap_map.get(named_return) if named_return and not return_callback and not array_dims else None
        if ap_ret:
            cleaned_ap = ' '.join(_clean_type_text(ap_ret[0]).split())
            if cleaned_ap:
                return_type = cleaned_ap
                return_decl = cleaned_ap
                return_stars = '*'
                array_dims = ap_ret[1]
                aggregate_return = False
        ptr_map = _fold_alias_map(_pointer_typedef_map(text), aliases)
        parsed = _promote_pointer_typedefs(parsed, ptr_map)
        ptr_ret = None if ap_ret else (
            ptr_map.get(named_return) if named_return and not return_callback and not array_dims else None
        )
        if ptr_ret:
            spelled_ret = _substitute_pointer_typedefs(ptr_ret, ptr_map)
            return_type = spelled_ret
            return_decl = spelled_ret
            aggregate_return = False
        elif not return_callback and not array_dims:
            spelled_ret = _substitute_pointer_typedefs(return_type, ptr_map)
            if spelled_ret != return_type:
                return_type = spelled_ret
                return_decl = spelled_ret
                aggregate_return = False
        fp_map = _fold_alias_map(_function_pointer_typedef_map(text), aliases)
        parsed = _promote_function_pointer_typedefs(parsed, fp_map)
        fp_ret = None if ptr_ret else (
            fp_map.get(named_return) if named_return and not return_callback and not array_dims else None
        )
        if fp_ret:
            cleaned_ret = ' '.join(_clean_type_text(fp_ret[0]).split())
            if cleaned_ret:
                return_type = cleaned_ret
                return_decl = cleaned_ret
                return_stars = '*'
                return_callback = fp_ret[1]
                aggregate_return = False
        fn_map = _fold_alias_map(_function_typedef_map(text), aliases)
        arr_map = _fold_alias_map(_array_typedef_map(text), aliases)
        parsed = _promote_function_typedefs(parsed, fn_map)
        parsed = _promote_array_typedefs(parsed, arr_map, ptr_map)
        parsed = _promote_function_typedefs(parsed, fn_map)
        return _apply_star_typedef_return({
            'name': function,
            'return_type': return_type,
            'return_decl': return_decl,
            'return_pointee': return_decl if array_dims or return_callback else '',
            'return_stars': return_stars,
            'return_array_dims': array_dims,
            'return_callback_args': return_callback,
            'returns_aggregate': aggregate_return,
            'parameters': parsed,
            'linkage': 'static' if is_static else 'global',
            'anonymous_types': anonymous_types,
            'variadic': variadic,
        }, fn_map, arr_map, ptr_map)
    return None


def _signature_for_cut(sym_scope: dict[str, Any], function: str, include_static: bool = False) -> dict[str, Any] | None:
    prototype = sym_scope.get('cut_prototype')
    if isinstance(prototype, str) and prototype.strip() and not include_static:
        text = prototype if ('{' in prototype or prototype.rstrip().endswith(';')) else prototype + ';'
        found = parse_c_function_signature(text, function)
        if found:
            return _with_local_typedefs(text, found)
    stored = (sym_scope.get('synthetic_signatures') or {}).get(function)
    if isinstance(stored, dict):
        return stored
    for raw_path in sym_scope.get('slice_sources') or []:
        path = Path(str(raw_path))
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        text = _expand_definition_macros(path, text)
        found = parse_c_function_signature(text, function, include_static=include_static)
        if found and (include_static or found.get('linkage') != 'static'):
            return _bind_aggregate_return(path, text, found)
    return None


def _aggregate_typedef_body(source: str, name: str) -> str:
    for found, body in _typedef_bodies(source):
        if found == name and re.match(r'typedef\s+(?:struct|union)\b', body):
            return body
    return ''


def _typedef_aggregate(source: str, name: str) -> bool:
    return bool(_aggregate_typedef_body(source, name))


def _typedef_alias_map(source: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for _name, body in _typedef_bodies(source):
        flat = ' '.join(body.split())
        if any(char in flat for char in '*()[]{}'):
            continue
        match = re.fullmatch(
            r'typedef\s+(?:(?:const|volatile|restrict)\s+)*([A-Za-z_]\w*)\s+([A-Za-z_]\w*)\s*;',
            flat,
        )
        if match is None or match.group(1) == match.group(2):
            continue
        found.setdefault(match.group(2), match.group(1))
    return found


def _chase_typedef(name: str, aliases: dict[str, str]) -> str:
    seen: set[str] = set()
    current = name
    while current in aliases and current not in seen and len(seen) < 8:
        seen.add(current)
        current = aliases[current]
    return current


def _fold_alias_map(mapping: dict[str, Any], aliases: dict[str, str]) -> dict[str, Any]:
    folded = dict(mapping)
    for alias in aliases:
        target = _chase_typedef(alias, aliases)
        if target in mapping and alias not in folded:
            folded[alias] = mapping[target]
    return folded


def _pointer_typedef_map(source: str) -> dict[str, str]:
    found: dict[str, str] = {}
    for name, body in _typedef_bodies(source):
        flat = ' '.join(body.split())
        if re.search(r'\(\s*\*', flat):
            continue
        match = re.fullmatch(r'typedef\s+(.+)\s*;', flat)
        if match is None:
            continue
        spelled = match.group(1).strip()
        visible: list[str] = []
        depth = 0
        for char in spelled:
            if char == '{':
                depth += 1
            elif char == '}':
                depth = max(0, depth - 1)
            elif depth == 0:
                visible.append(char)
        if '*' not in ''.join(visible):
            continue
        stripped = re.sub(rf'\s+{re.escape(name)}$', '', spelled).strip()
        if stripped == spelled:
            stripped = re.sub(rf'(?<=\*)\s*{re.escape(name)}$', '', spelled).strip()
        if stripped and '*' in stripped and stripped != spelled:
            found.setdefault(name, ' '.join(stripped.split()))
    return found


def _array_pointer_typedef_map(source: str) -> dict[str, tuple[str, list[int]]]:
    found: dict[str, tuple[str, list[int]]] = {}
    for _name, body in _typedef_bodies(source):
        flat = ' '.join(body.split())
        match = re.fullmatch(
            r'typedef\s+(.+?)\s*\(\s*\*(?:\s*const\s*)?\s*([A-Za-z_]\w*)\s*\)\s*((?:\[\s*\d*\s*\])+)\s*;',
            flat,
        )
        if match is None:
            continue
        dims: list[int] = []
        for dim in re.finditer(r'\[\s*(\d*)\s*\]', match.group(3)):
            length = dim.group(1)
            size = int(length) if length else 16
            dims.append(size if size > 0 else 16)
        if not dims:
            continue
        found.setdefault(match.group(2), (match.group(1).strip(), dims))
    return found


def _promote_array_pointer_typedefs(parameters: list[dict[str, Any]],
                                    mapping: dict[str, tuple[str, list[int]]]) -> list[dict[str, Any]]:
    if not mapping:
        return parameters
    updated: list[dict[str, Any]] = []
    for item in parameters:
        type_name = ' '.join(str(item.get('type_text') or '').split())
        spec = mapping.get(type_name) if (
            item.get('kind') in {'struct_value', 'integer'}
            and '*' not in type_name
            and ' ' not in type_name
        ) else None
        if spec is None:
            updated.append(item)
            continue
        element, dims = spec
        shown = ''.join(f'[{size}]' for size in dims)
        record = _pointer_to_array_param(
            f'{element} (*{item["name"]}){shown}',
            int(item['index']),
        )
        updated.append(record or item)
    return updated


def _apply_array_pointer_return(signature: dict[str, Any],
                                mapping: dict[str, tuple[str, list[int]]]) -> dict[str, Any]:
    if signature.get('return_callback_args') or signature.get('return_array_dims'):
        return signature
    ret = str(signature.get('return_type') or '')
    if signature.get('returns_aggregate') or '*' in ret:
        return signature
    words = ret.split()
    if len(words) != 1 or words[0] not in mapping:
        return signature
    element, dims = mapping[words[0]]
    cleaned = ' '.join(_clean_type_text(element).split())
    if not cleaned:
        return signature
    bound = dict(signature)
    bound['return_type'] = cleaned
    bound['return_decl'] = cleaned
    bound['return_pointee'] = cleaned
    bound['return_stars'] = '*'
    bound['return_array_dims'] = dims
    bound['returns_aggregate'] = False
    return bound


def _function_typedef_map(source: str) -> dict[str, tuple[str, str]]:
    found: dict[str, tuple[str, str]] = {}
    for _name, body in _typedef_bodies(source):
        flat = ' '.join(body.split())
        if re.search(r'\(\s*\*', flat):
            continue
        match = re.fullmatch(r'typedef\s+(.+?)\s+([A-Za-z_]\w*)\s*\((.*)\)\s*;', flat)
        if match is None:
            continue
        args = ' '.join(match.group(3).split()) or 'void'
        found.setdefault(match.group(2), (match.group(1).strip(), args))
    return found


def _array_typedef_map(source: str) -> dict[str, tuple[str, list[int]]]:
    found: dict[str, tuple[str, list[int]]] = {}
    for _name, body in _typedef_bodies(source):
        flat = ' '.join(body.split())
        if '(' in flat:
            continue
        match = re.fullmatch(
            r'typedef\s+(.+?)\s+([A-Za-z_]\w*)\s*((?:\[\s*\d*\s*\])+)\s*;',
            flat,
        )
        if match is None:
            continue
        dims: list[int] = []
        for dim in re.finditer(r'\[\s*(\d*)\s*\]', match.group(3)):
            length = dim.group(1)
            size = int(length) if length else 16
            dims.append(size if size > 0 else 16)
        if dims:
            found.setdefault(match.group(2), (match.group(1).strip(), dims))
    return found


def _one_star_pointee(item: dict[str, Any]) -> str:
    if item.get('kind') != 'pointer':
        return ''
    shown = str(item.get('decl_type') or item.get('type_text') or '')
    if shown.count('*') != 1:
        return ''
    pointee = ' '.join(word for word in shown.replace('*', ' ').split() if word != 'const')
    if ' ' in pointee or not re.fullmatch(r'[A-Za-z_]\w*', pointee):
        return ''
    return pointee


def _value_array_param(element: str, name: str, dims: list[int], index: int) -> dict[str, Any]:
    cleaned = ' '.join(_clean_type_text(element).split()) or element
    return {
        'kind': 'buffer',
        'name': name,
        'type_text': cleaned,
        'decl_type': cleaned,
        'pointee': cleaned,
        'array_len': None,
        'value_array_dims': dims,
        'index': index,
    }


def _promote_function_typedefs(parameters: list[dict[str, Any]],
                               mapping: dict[str, tuple[str, str]]) -> list[dict[str, Any]]:
    if not mapping:
        return parameters
    updated: list[dict[str, Any]] = []
    for item in parameters:
        type_name = ' '.join(str(item.get('type_text') or '').split())
        if item.get('kind') == 'pointer' and not item.get('array_dims') and not item.get('value_array_dims'):
            shown = ' '.join(str(item.get('decl_type') or item.get('type_text') or '').split())
            stars = shown.count('*')
            base = [
                word for word in shown.replace('*', ' ').split()
                if word not in {'const', 'volatile', 'restrict'}
            ]
            if stars >= 2 and len(base) == 1 and base[0] in mapping and stars <= 8:
                spec = mapping[base[0]]
                record = _callback_record(spec[0], str(item['name']), spec[1], int(item['index']))
                if record is not None:
                    depth = stars - 1
                    record['callback_address_depth'] = depth
                    record['decl_type'] = f'{record["type_text"]} ({"*" * stars}{item["name"]})({record["args_text"]})'
                    updated.append(record)
                    continue
        if item.get('value_array_dims'):
            element = ' '.join(str(item.get('type_text') or item.get('pointee') or '').split())
            base = element.replace('*', ' ').split()
            if len(base) == 1 and base[0] in mapping and element.count('*') == 1:
                spec = mapping[base[0]]
                shown = ''.join(f'[{int(size)}]' for size in item['value_array_dims'])
                record = _array_of_callbacks(
                    f'{spec[0]} (*{item["name"]}{shown})({spec[1]})',
                    int(item['index']),
                )
                updated.append(record or item)
                continue
        element = ' '.join(str(item.get('pointee') or '').split())
        if (
            item.get('kind') == 'buffer'
            and item.get('array_len')
            and element in mapping
            and '*' not in element
            and ' ' not in element
        ):
            spec = mapping[element]
            record = _array_of_callbacks(
                f'{spec[0]} (*{item["name"]}[{int(item["array_len"])}])({spec[1]})',
                int(item['index']),
            )
            updated.append(record or item)
            continue
        spec = None
        if (
            item.get('kind') in {'struct_value', 'integer'}
            and type_name in mapping
            and '*' not in type_name
            and ' ' not in type_name
        ):
            spec = mapping[type_name]
        else:
            pointee = _one_star_pointee(item)
            if pointee in mapping:
                spec = mapping[pointee]
        if spec is None:
            updated.append(item)
            continue
        record = _callback_record(spec[0], str(item['name']), spec[1], int(item['index']))
        updated.append(record or item)
    return updated


def _flatten_array_spec(element: str,
                        dims: list[int],
                        mapping: dict[str, tuple[str, list[int]]]) -> tuple[str, list[int]]:
    current = ' '.join(element.split())
    found = [int(size) for size in dims]
    seen: set[str] = set()
    for _step in range(8):
        if (
            not current
            or current in seen
            or current not in mapping
            or ' ' in current
            or '*' in current
        ):
            break
        seen.add(current)
        inner, more = mapping[current]
        found.extend(int(size) for size in more)
        current = ' '.join(str(inner).split())
    return current, found


def _promote_array_typedefs(parameters: list[dict[str, Any]],
                            mapping: dict[str, tuple[str, list[int]]],
                            pointer_map: dict[str, str] | None = None) -> list[dict[str, Any]]:
    if not mapping:
        return parameters
    pointers = pointer_map or {}
    updated: list[dict[str, Any]] = []
    for item in parameters:
        type_name = ' '.join(str(item.get('type_text') or '').split())
        element_name = ' '.join(str(item.get('pointee') or '').split())
        if (
            item.get('kind') == 'buffer'
            and item.get('array_len')
            and element_name in mapping
            and '*' not in element_name
            and ' ' not in element_name
        ):
            element, dims = mapping[element_name]
            element, dims = _flatten_array_spec(element, [int(item['array_len']), *dims], mapping)
            element = _substitute_pointer_typedefs(element, pointers)
            updated.append(_value_array_param(element, str(item['name']), dims, int(item['index'])))
            continue
        if (
            item.get('kind') in {'struct_value', 'integer'}
            and type_name in mapping
            and '*' not in type_name
            and ' ' not in type_name
        ):
            element, dims = mapping[type_name]
            element, dims = _flatten_array_spec(element, dims, mapping)
            element = _substitute_pointer_typedefs(element, pointers)
            updated.append(_value_array_param(element, str(item['name']), dims, int(item['index'])))
            continue
        pointee = _one_star_pointee(item)
        if pointee in mapping:
            element, dims = mapping[pointee]
            element, dims = _flatten_array_spec(element, dims, mapping)
            element = _substitute_pointer_typedefs(element, pointers)
            shown = ''.join(f'[{size}]' for size in dims)
            record = _pointer_to_array_param(
                f'{element} (*{item["name"]}){shown}',
                int(item['index']),
            )
            updated.append(record or item)
            continue
        updated.append(item)
    return updated


def _apply_star_typedef_return(signature: dict[str, Any],
                               functions: dict[str, tuple[str, str]],
                               arrays: dict[str, tuple[str, list[int]]],
                               pointer_map: dict[str, str] | None = None) -> dict[str, Any]:
    if signature.get('return_callback_args') or signature.get('return_array_dims') or signature.get('returns_aggregate'):
        return signature
    ret = ' '.join(str(signature.get('return_type') or '').split())
    match = re.fullmatch(r'([A-Za-z_]\w*)(?:\s*\*)+', ret)
    if match is None or ret.count('*') > 8:
        return signature
    name = match.group(1)
    stars = '*' * ret.count('*')
    if name in functions:
        cleaned = ' '.join(_clean_type_text(functions[name][0]).split())
        if not cleaned:
            return signature
        bound = dict(signature)
        bound['return_type'] = cleaned
        bound['return_decl'] = cleaned
        bound['return_pointee'] = cleaned
        bound['return_stars'] = stars
        bound['return_callback_args'] = functions[name][1]
        bound['returns_aggregate'] = False
        return bound
    if name in arrays:
        element, dims = arrays[name]
        element, dims = _flatten_array_spec(element, dims, arrays)
        element = _substitute_pointer_typedefs(element, pointer_map or {})
        cleaned = ' '.join(_clean_type_text(element).split())
        if not cleaned:
            return signature
        bound = dict(signature)
        bound['return_type'] = cleaned
        bound['return_decl'] = cleaned
        bound['return_pointee'] = cleaned
        bound['return_stars'] = stars
        bound['return_array_dims'] = dims
        bound['returns_aggregate'] = False
        return bound
    return signature


def _substitute_pointer_typedefs(type_text: str, mapping: dict[str, str]) -> str:
    current = ' '.join(type_text.split())
    for _step in range(8):
        rebuilt: list[str] = []
        changed = False
        for word in current.split():
            stars = word.count('*')
            bare = word.replace('*', '')
            if bare and bare in mapping:
                spelling = mapping[bare]
                suffix = '*' * stars
                rebuilt.append(spelling + (f' {suffix}' if suffix else ''))
                changed = True
            else:
                rebuilt.append(word)
        updated = ' '.join(rebuilt)
        if not changed or updated == current:
            return current
        current = updated
    return current


def _promote_pointer_typedefs(parameters: list[dict[str, Any]],
                              mapping: dict[str, str]) -> list[dict[str, Any]]:
    if not mapping:
        return parameters
    current = list(parameters)
    for _step in range(8):
        updated: list[dict[str, Any]] = []
        changed = False
        for item in current:
            type_name = ' '.join(str(item.get('type_text') or '').split())
            spelled = mapping.get(type_name) if (
                item.get('kind') in {'struct_value', 'integer'}
                and '*' not in type_name
                and ' ' not in type_name
            ) else None
            shown = ' '.join(str(item.get('decl_type') or item.get('type_text') or '').split())
            if item.get('kind') == 'buffer' and item.get('array_len') and spelled is None:
                element = ' '.join(str(item.get('type_text') or item.get('pointee') or '').split())
                expanded_element = _substitute_pointer_typedefs(element, mapping)
                if expanded_element == element:
                    updated.append(item)
                    continue
                updated.append(_value_array_param(
                    expanded_element,
                    str(item['name']),
                    [int(item['array_len'])],
                    int(item['index']),
                ))
                changed = True
                continue
            if item.get('value_array_dims') or item.get('array_dims'):
                updated.append(item)
                continue
            expanded = _substitute_pointer_typedefs(spelled if spelled is not None else shown, mapping)
            if spelled is None and expanded == shown:
                updated.append(item)
                continue
            record = _parse_param_text(f'{expanded} {item["name"]}', int(item['index']))
            updated.append(record or item)
            if record is not None:
                changed = True
        current = updated
        if not changed:
            break
    return current


def _function_pointer_typedef_map(source: str) -> dict[str, tuple[str, str]]:
    found: dict[str, tuple[str, str]] = {}
    for _name, body in _typedef_bodies(source):
        flat = ' '.join(body.split())
        match = re.fullmatch(
            r'typedef\s+(.+?)\s*\(\s*\*(?:\s*const\s*)?\s*([A-Za-z_]\w*)\s*\)\s*\((.*)\)\s*;',
            flat,
        )
        if match is None:
            continue
        args = ' '.join(match.group(3).split()) or 'void'
        found.setdefault(match.group(2), (match.group(1).strip(), args))
    return found


def _promote_function_pointer_typedefs(parameters: list[dict[str, Any]],
                                       mapping: dict[str, tuple[str, str]]) -> list[dict[str, Any]]:
    if not mapping:
        return parameters
    updated: list[dict[str, Any]] = []
    for item in parameters:
        type_name = ' '.join(str(item.get('type_text') or '').split())
        element = ' '.join(str(item.get('pointee') or type_name).split())
        record = None
        if item.get('kind') == 'buffer' and item.get('array_len') and '*' not in element and ' ' not in element:
            spec = mapping.get(element)
            if spec is not None:
                record = _array_of_callbacks(
                    f'{spec[0]} (*{item["name"]}[{int(item["array_len"])}])({spec[1]})',
                    int(item['index']),
                )
        elif (
            item.get('kind') in {'struct_value', 'integer'}
            and type_name in mapping
            and '*' not in type_name
            and ' ' not in type_name
        ):
            spec = mapping[type_name]
            record = _callback_record(spec[0], str(item['name']), spec[1], int(item['index']))
        updated.append(record or item)
    return updated


def _apply_function_pointer_return(signature: dict[str, Any],
                                   mapping: dict[str, tuple[str, str]]) -> dict[str, Any]:
    if signature.get('return_callback_args') or signature.get('return_array_dims'):
        return signature
    ret = str(signature.get('return_type') or '')
    if signature.get('returns_aggregate') or '*' in ret:
        return signature
    words = ret.split()
    if len(words) != 1:
        return signature
    spec = mapping.get(words[0])
    if spec is None:
        return signature
    cleaned = ' '.join(_clean_type_text(spec[0]).split())
    if not cleaned:
        return signature
    bound = dict(signature)
    bound['return_type'] = cleaned
    bound['return_decl'] = cleaned
    bound['return_pointee'] = cleaned
    bound['return_stars'] = '*'
    bound['return_callback_args'] = spec[1]
    bound['returns_aggregate'] = False
    return bound


_AGGREGATE_TYPEDEF_CACHE: dict[str, dict[str, str]] = {}
_FP_TYPEDEF_CACHE: dict[str, dict[str, tuple[str, str]]] = {}
_POINTER_TYPEDEF_CACHE: dict[str, dict[str, str]] = {}
_ARRAY_POINTER_TYPEDEF_CACHE: dict[str, dict[str, tuple[str, list[int]]]] = {}
_FUNCTION_TYPEDEF_CACHE: dict[str, dict[str, tuple[str, str]]] = {}
_ARRAY_TYPEDEF_CACHE: dict[str, dict[str, tuple[str, list[int]]]] = {}
_ALIAS_TYPEDEF_CACHE: dict[str, dict[str, str]] = {}


def _cached_aggregate_typedefs(path: Path) -> dict[str, str]:
    key = str(path)
    cached = _AGGREGATE_TYPEDEF_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        text = ''
    found: dict[str, str] = {}
    for name, body in _typedef_bodies(text):
        if re.match(r'typedef\s+(?:struct|union)\b', body):
            found.setdefault(name, body)
    _AGGREGATE_TYPEDEF_CACHE[key] = found
    return found


def _decl_header_paths(path: Path, text: str) -> list[Path]:
    found: list[Path] = []
    if path.parent.is_dir():
        found.extend(sorted(item for item in path.parent.glob('*.h') if item.is_file()))
    roots = _nearby_source_roots(path)
    if roots and re.search(r'(?m)^[ \t]*#[ \t]*include\b', text):
        seen = {str(item) for item in found}
        pending = [text]
        while pending and len(found) < 128:
            current = pending.pop(0)
            for name in _direct_includes(current):
                if len(found) >= 128:
                    break
                header = next((item for root in roots if (item := _header_file(root, name))), None)
                if header is None or header in seen:
                    continue
                seen.add(header)
                if 'win32' in Path(header).parts:
                    continue
                header_path = Path(header)
                try:
                    header_text = header_path.read_text(encoding='utf-8', errors='replace')
                except OSError:
                    continue
                found.append(header_path)
                pending.append(header_text)
    return found


def _cached_pointer_typedefs(path: Path) -> dict[str, str]:
    key = str(path)
    cached = _POINTER_TYPEDEF_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        text = ''
    found = _pointer_typedef_map(text)
    _POINTER_TYPEDEF_CACHE[key] = found
    return found


def _cached_array_pointer_typedefs(path: Path) -> dict[str, tuple[str, list[int]]]:
    key = str(path)
    cached = _ARRAY_POINTER_TYPEDEF_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        text = ''
    found = _array_pointer_typedef_map(text)
    _ARRAY_POINTER_TYPEDEF_CACHE[key] = found
    return found


def _bind_pointer_typedefs(path: Path, text: str, signature: dict[str, Any]) -> dict[str, Any]:
    names = _function_pointer_typedef_names(signature)
    if not names:
        return signature
    aliases = dict(_typedef_alias_map(text))
    mapping = dict(_pointer_typedef_map(text))
    arrays = dict(_array_pointer_typedef_map(text))
    if any(name not in mapping and name not in arrays and _chase_typedef(name, aliases) not in mapping and _chase_typedef(name, aliases) not in arrays for name in names):
        for header in _decl_header_paths(path, text):
            aliases.update(_cached_alias_typedefs(header))
            mapping.update(_cached_pointer_typedefs(header))
            arrays.update(_cached_array_pointer_typedefs(header))
            if all(name in mapping or name in arrays or _chase_typedef(name, aliases) in mapping or _chase_typedef(name, aliases) in arrays for name in names):
                break
    mapping = _fold_alias_map(mapping, aliases)
    arrays = _fold_alias_map(arrays, aliases)
    promoted = _promote_array_pointer_typedefs(list(signature.get('parameters') or []), arrays)
    promoted = _promote_pointer_typedefs(promoted, mapping)
    bound = signature
    if promoted != list(signature.get('parameters') or []):
        bound = dict(signature)
        bound['parameters'] = promoted
    bound = _apply_array_pointer_return(bound, arrays)
    ret = str(bound.get('return_type') or '')
    words = ret.split()
    if (
        not bound.get('return_callback_args')
        and not bound.get('return_array_dims')
        and not bound.get('returns_aggregate')
        and len(words) == 1
        and words[0] in mapping
    ):
        spelled = _substitute_pointer_typedefs(mapping[words[0]], mapping)
        bound = dict(bound)
        bound['return_type'] = spelled
        bound['return_decl'] = spelled
        bound['returns_aggregate'] = False
    expanded_ret = _substitute_pointer_typedefs(str(bound.get('return_type') or ''), mapping)
    if expanded_ret != str(bound.get('return_type') or ''):
        bound = dict(bound)
        bound['return_type'] = expanded_ret
        bound['return_decl'] = expanded_ret
        bound['returns_aggregate'] = False
    value_arrays = _fold_alias_map(dict(_array_typedef_map(text)), aliases)
    if any(name not in value_arrays and _chase_typedef(name, aliases) not in value_arrays for name in names):
        for header in _decl_header_paths(path, text):
            aliases.update(_cached_alias_typedefs(header))
            value_arrays.update(_cached_array_typedefs(header))
            if all(name in value_arrays or _chase_typedef(name, aliases) in value_arrays for name in names):
                break
    value_arrays = _fold_alias_map(value_arrays, aliases)
    array_params = _promote_array_typedefs(list(bound.get('parameters') or []), value_arrays, mapping)
    if array_params != list(bound.get('parameters') or []):
        bound = dict(bound)
        bound['parameters'] = array_params
    return _apply_star_typedef_return(bound, {}, value_arrays, mapping)


def _cached_alias_typedefs(path: Path) -> dict[str, str]:
    key = str(path)
    cached = _ALIAS_TYPEDEF_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        text = ''
    found = _typedef_alias_map(text)
    _ALIAS_TYPEDEF_CACHE[key] = found
    return found


def _cached_array_typedefs(path: Path) -> dict[str, tuple[str, list[int]]]:
    key = str(path)
    cached = _ARRAY_TYPEDEF_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        text = ''
    found = _array_typedef_map(text)
    _ARRAY_TYPEDEF_CACHE[key] = found
    return found


def _cached_function_typedefs(path: Path) -> dict[str, tuple[str, str]]:
    key = str(path)
    cached = _FUNCTION_TYPEDEF_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        text = ''
    found = _function_typedef_map(text)
    _FUNCTION_TYPEDEF_CACHE[key] = found
    return found


def _cached_function_pointer_typedefs(path: Path) -> dict[str, tuple[str, str]]:
    key = str(path)
    cached = _FP_TYPEDEF_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        text = ''
    found = _function_pointer_typedef_map(text)
    _FP_TYPEDEF_CACHE[key] = found
    return found


def _function_pointer_typedef_names(signature: dict[str, Any]) -> list[str]:
    names: list[str] = []
    ret = str(signature.get('return_type') or '')
    if (
        not signature.get('return_callback_args')
        and not signature.get('return_array_dims')
        and not signature.get('returns_aggregate')
        and '*' not in ret
    ):
        words = ret.split()
        if len(words) == 1 and words[0] not in _PROTO_INTEGER_WORDS:
            names.append(words[0])
    else:
        star = re.fullmatch(r'([A-Za-z_]\w*)(?:\s*\*)+', ' '.join(ret.split()))
        if (
            star
            and not signature.get('return_callback_args')
            and not signature.get('return_array_dims')
            and star.group(1) not in _PROTO_INTEGER_WORDS
        ):
            names.append(star.group(1))
    for item in signature.get('parameters') or []:
        pointee = _one_star_pointee(item)
        if pointee and pointee not in _PROTO_INTEGER_WORDS:
            names.append(pointee)
        if item.get('kind') == 'pointer' and not item.get('array_dims'):
            shown = ' '.join(str(item.get('decl_type') or item.get('type_text') or '').split())
            base = [
                word for word in shown.replace('*', ' ').split()
                if word not in {'const', 'volatile', 'restrict'}
            ]
            if len(base) == 1 and base[0] not in _PROTO_INTEGER_WORDS and shown.count('*') >= 2:
                names.append(base[0])
        if item.get('value_array_dims'):
            element = ' '.join(str(item.get('type_text') or item.get('pointee') or '').split())
            base = element.replace('*', ' ').split()
            if len(base) == 1 and base[0] not in _PROTO_INTEGER_WORDS:
                names.append(base[0])
        if item.get('kind') == 'buffer' and item.get('array_len'):
            element = ' '.join(str(item.get('pointee') or '').split())
            if element and '*' not in element and ' ' not in element and element not in _PROTO_INTEGER_WORDS:
                names.append(element)
            continue
        if item.get('kind') not in {'struct_value', 'integer'}:
            continue
        type_name = ' '.join(str(item.get('type_text') or '').split())
        if type_name and '*' not in type_name and ' ' not in type_name and type_name not in _PROTO_INTEGER_WORDS:
            names.append(type_name)
    return names


def _bind_function_pointer_params(path: Path, text: str, signature: dict[str, Any]) -> dict[str, Any]:
    names = _function_pointer_typedef_names(signature)
    if not names:
        return signature
    aliases = dict(_typedef_alias_map(text))
    mapping = _fold_alias_map(dict(_function_pointer_typedef_map(text)), aliases)
    if any(name not in mapping and _chase_typedef(name, aliases) not in mapping for name in names):
        for header in _decl_header_paths(path, text):
            aliases.update(_cached_alias_typedefs(header))
            mapping.update(_cached_function_pointer_typedefs(header))
            if all(name in mapping or _chase_typedef(name, aliases) in mapping for name in names):
                break
    mapping = _fold_alias_map(mapping, aliases)
    promoted = _promote_function_pointer_typedefs(list(signature.get('parameters') or []), mapping)
    bound = signature
    if promoted != list(signature.get('parameters') or []):
        bound = dict(signature)
        bound['parameters'] = promoted
    functions = _fold_alias_map(dict(_function_typedef_map(text)), aliases)
    if any(name not in functions and _chase_typedef(name, aliases) not in functions for name in names):
        for header in _decl_header_paths(path, text):
            aliases.update(_cached_alias_typedefs(header))
            functions.update(_cached_function_typedefs(header))
            if all(name in functions or name in mapping or _chase_typedef(name, aliases) in functions or _chase_typedef(name, aliases) in mapping for name in names):
                break
    functions = _fold_alias_map(functions, aliases)
    fn_params = _promote_function_typedefs(list(bound.get('parameters') or []), functions)
    if fn_params != list(bound.get('parameters') or []):
        bound = dict(bound)
        bound['parameters'] = fn_params
    return _apply_star_typedef_return(_apply_function_pointer_return(bound, mapping), functions, {})


def _bind_aggregate_return(path: Path, text: str, signature: dict[str, Any]) -> dict[str, Any]:
    bound = _with_local_typedefs(text, signature)
    ret = str(bound.get('return_type') or '')
    if not bound.get('returns_aggregate') and '*' not in ret:
        words = ret.split()
        if len(words) == 1 and re.fullmatch(r'[A-Za-z_]\w*', words[0]):
            name = words[0]
            body = _aggregate_typedef_body(text, name)
            if not body:
                for header in _decl_header_paths(path, text):
                    body = _cached_aggregate_typedefs(header).get(name, '')
                    if body:
                        break
            if body:
                bound = dict(bound)
                bound['returns_aggregate'] = True
                bodies = list(bound.get('local_typedef_bodies') or [])
                if body not in bodies:
                    bodies.insert(0, body)
                bound['local_typedef_bodies'] = bodies
    return _bind_function_pointer_params(path, text, _bind_pointer_typedefs(path, text, bound))


def _is_scalar_word(word: str) -> bool:
    if word in _PROTO_INTEGER_WORDS:
        return True
    if word.endswith(('_t', '_type', '_e', 'Code', 'Result', 'Status')):
        return True
    return word.isupper() and len(word) > 1


def _decl_macro_name(name: str) -> bool:
    return any(part in name for part in ('DECLARE', 'EXPORT', 'EXTERN', 'PUBLIC', 'API', 'DLLEXPORT', 'INLINE'))


def _single_macro_argument(text: str) -> bool:
    depth = 0
    for char in text:
        if char in '([{':
            depth += 1
        elif char in ')]}':
            depth = max(0, depth - 1)
        elif char == ',' and depth == 0:
            return False
    return True


def _strip_gnu_declspecs(text: str) -> str:
    current = text
    for token in ('__attribute__', '__declspec', '__attribute'):
        index = 0
        while index < len(current):
            at = current.find(token, index)
            if at < 0:
                break
            before = current[at - 1] if at else ' '
            after_at = at + len(token)
            after = current[after_at:after_at + 1]
            if before.isalnum() or before == '_' or (after and (after.isalnum() or after == '_')):
                index = after_at
                continue
            paren = _skip_sig_space(current, after_at)
            if paren >= len(current) or current[paren] != '(':
                index = after_at
                continue
            end = _proto_match(current, paren, '(', ')')
            if end < 0:
                index = after_at
                continue
            current = current[:at] + ' ' + current[end + 1:]
            index = at
    return current


def _replace_decl_macros(text: str) -> str:
    pieces: list[str] = []
    cursor = 0
    changed = False
    for match in re.finditer(r'(?<![\w])([A-Z][A-Z0-9_]*)\s*\(', text):
        if match.start() < cursor or not _decl_macro_name(match.group(1)):
            continue
        paren = match.end() - 1
        end = _proto_match(text, paren, '(', ')')
        if end < 0:
            continue
        inner = text[paren + 1:end].strip()
        if not inner or not _single_macro_argument(inner):
            continue
        pieces.append(text[cursor:match.start()])
        pieces.append(inner)
        cursor = end + 1
        changed = True
    if not changed:
        return text
    pieces.append(text[cursor:])
    return ''.join(pieces)


def _unwrap_decl_macros(text: str) -> str:
    current = ' '.join(text.replace('\n', ' ').split())
    for _pass in range(8):
        updated = ' '.join(_replace_decl_macros(_strip_gnu_declspecs(current)).split())
        if updated == current:
            return current
        current = updated
    return current


def _decl_type_text(text: str) -> str:
    cleaned = re.sub(
        r'\b(?:static|inline|extern|_Noreturn|__inline|__inline__|volatile|restrict|register)\b',
        ' ',
        text,
    )
    cleaned = re.sub(r'\b[A-Za-z_][A-Za-z0-9_]*INLINE\b', ' ', cleaned)
    cleaned = _drop_calling_convention(cleaned)
    return _drop_leading_caps(_drop_export_macros(cleaned))


def _drop_leading_caps(text: str) -> str:
    words = text.split()
    ident_at = [index for index, word in enumerate(words) if re.fullmatch(r'[A-Za-z_]\w*', word)]
    if len(ident_at) < 2:
        return ' '.join(words)
    last = ident_at[-1]
    kept = [
        word for index, word in enumerate(words)
        if index == last or not (word.isupper() and len(word) > 1 and re.fullmatch(r'[A-Za-z_]\w*', word))
    ]
    return ' '.join(kept) if kept else ' '.join(words)


def _drop_export_macros(text: str) -> str:
    words = text.split()
    kept = [
        word for word in words
        if not (word.isupper() and _decl_macro_name(word))
    ]
    if not kept or len(kept) == len(words):
        return ' '.join(words)
    return ' '.join(kept)


_HEADER_MACRO_CACHE: dict[str, dict[str, tuple[list[str], str]]] = {}


def _macro_defines_function(body: str, param: str) -> bool:
    token = re.escape(param)
    if re.search(rf'(?<![\w]){token}\s*##|##\s*{token}(?![\w])', body):
        return True
    if re.search(rf'(?<![\w]){token}\s*\(', body):
        return True
    if re.search(rf'\*\s*{token}(?![\w])', body):
        return True
    if re.search(rf'(?<![\w])[A-Za-z_]\w*\s*\(\s*{token}\s*\)\s*\(', body):
        return True
    previous = re.search(rf'([A-Za-z_]\w*)\s+{token}(?![\w])', body)
    if previous is None:
        return False
    word = previous.group(1)
    if word in {'return', 'if', 'while', 'for', 'switch', 'sizeof', 'case', 'goto', 'else'}:
        return False
    return (
        word in _PROTO_INTEGER_WORDS
        or word in {'struct', 'union', 'enum', 'const', 'volatile', 'signed', 'unsigned', 'static', 'inline', 'extern'}
        or _is_scalar_word(word)
    )


def _params_are_declarator(body: str, params: list[str]) -> bool:
    if len(params) < 2:
        return False
    stripped = body
    for param in sorted(params, key=len, reverse=True):
        stripped = re.sub(rf'(?<![\w]){re.escape(param)}(?![\w])', ' ', stripped)
    if re.search(r'[+\-/%&|^!=<>?:]', stripped):
        return False
    words = re.findall(r'[A-Za-z_]\w*', stripped)
    return all(
        word in _PROTO_INTEGER_WORDS
        or word in {'struct', 'union', 'enum', 'const', 'volatile', 'signed', 'unsigned', 'static', 'inline', 'extern', 'void'}
        or _is_scalar_word(word)
        for word in words
    )


def _substitute_macro_param(body: str, param: str, arg: str) -> str:
    token = re.escape(param)
    current = body
    for _step in range(4):
        updated = re.sub(
            rf'([A-Za-z_]\w*)\s*##\s*{token}\s*##\s*([A-Za-z_]\w*)',
            lambda match: match.group(1) + arg + match.group(2),
            current,
        )
        updated = re.sub(
            rf'([A-Za-z_]\w*)\s*##\s*{token}(?![\w])',
            lambda match: match.group(1) + arg,
            updated,
        )
        updated = re.sub(
            rf'(?<![\w]){token}\s*##\s*([A-Za-z_]\w*)',
            lambda match: arg + match.group(1),
            updated,
        )
        if updated == current:
            break
        current = updated
    current = re.sub(rf'(?<![\w]){token}(?![\w])', lambda _match: arg, current)
    for _step in range(4):
        updated = re.sub(
            r'([A-Za-z_]\w*)\s*##\s*([A-Za-z_]\w*)',
            lambda match: match.group(1) + match.group(2),
            current,
        )
        if updated == current:
            break
        current = updated
    return current


def _macro_call_args(text: str) -> list[str] | None:
    parts: list[str] = []
    start = 0
    depth = 0
    for index, char in enumerate(text):
        if char in '([{':
            depth += 1
        elif char in ')]}':
            if depth == 0:
                return None
            depth -= 1
        elif char == ',' and depth == 0:
            part = text[start:index].strip()
            if not part:
                return None
            parts.append(part)
            start = index + 1
    if depth:
        return None
    tail = text[start:].strip()
    if not tail:
        return None if parts else []
    parts.append(tail)
    return parts


def _macros_in_text(text: str) -> dict[str, tuple[list[str], str]]:
    found: dict[str, tuple[list[str], str]] = {}
    pattern = re.compile(
        r'^[ \t]*#\s*define\s+([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*\)\s+(.+)$',
        re.M,
    )
    for match in pattern.finditer(_logical_source(text)):
        body = match.group(3).split('/*')[0].strip()
        params = [item.strip() for item in match.group(2).split(',')]
        if not any(_macro_defines_function(body, param) for param in params) and not _params_are_declarator(body, params):
            continue
        found[match.group(1)] = (params, body)
    return found


def _header_macros(directory: Path) -> dict[str, tuple[list[str], str]]:
    key = str(directory)
    cached = _HEADER_MACRO_CACHE.get(key)
    if cached is not None:
        return cached
    found: dict[str, tuple[list[str], str]] = {}
    if directory.is_dir():
        for header in sorted(directory.glob('*.h')):
            try:
                text = header.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            found.update(_macros_in_text(text))
    _HEADER_MACRO_CACHE[key] = found
    return found


_PARAM_DECL_PIECE = re.compile(
    r'(?:(?:const|volatile|struct|union|enum|unsigned|signed|long|short)\s+)*'
    r'[A-Za-z_]\w*'
    r'(?:\s*\*+\s*|\s+)'
    r'[A-Za-z_]\w*'
    r'(?:\s*\[[^\]]*\])*\s*'
)


def _object_body_is_param_list(name: str, body: str) -> bool:
    if not any(part in name for part in ('PARAMETER', 'PARAMS', 'ARGS')):
        return False
    if not body or any(char in body for char in '(){}') or re.search(r'[+\-/%&|^!=<>?:]', body):
        return False
    parts = [part.strip() for part in body.split(',')]
    if not parts or any(not part for part in parts):
        return False
    return all(_PARAM_DECL_PIECE.fullmatch(part) for part in parts)


def _object_body_is_decl(body: str) -> bool:
    if not body or body.startswith('__attribute__') or body.startswith('__declspec'):
        return True
    if '(' in body or ')' in body or re.search(r'[{}]', body):
        return False
    if re.fullmatch(r'[A-Z][A-Z0-9_]*', body):
        return True
    words = re.findall(r'[A-Za-z_]\w*', body)
    if not words or re.search(r'[+\-/%&|^!=<>?:]', body):
        return False
    return any(
        word in {
            'void', 'char', 'int', 'short', 'long', 'signed', 'unsigned', 'const',
            'struct', 'union', 'enum', 'float', 'double', 'bool', '_Bool',
        }
        or word.endswith(('_t', '_e', '_type'))
        or (word.isupper() and len(word) > 1)
        for word in words
    )


def _object_decl_macros(text: str) -> dict[str, str]:
    found: dict[str, str] = {}
    pattern = re.compile(
        r'^[ \t]*#\s*define\s+([A-Z][A-Z0-9_]*)(?:[ \t]+([^\n]*))?$',
        re.M,
    )
    for match in pattern.finditer(_logical_source(text)):
        body = (match.group(2) or '').split('/*')[0].strip()
        if body.endswith('\\') or not (
            _object_body_is_decl(body) or _object_body_is_param_list(match.group(1), body)
        ):
            continue
        found[match.group(1)] = body
    return found


def _expand_object_decl_macros(text: str, macros: dict[str, str]) -> str:
    if not macros:
        return text
    pattern = re.compile(
        r'(?<![\w#])(' + '|'.join(re.escape(name) for name in sorted(macros, key=len, reverse=True)) + r')(?![\w])'
    )
    pieces: list[str] = []
    cursor = 0
    index = 0
    while index < len(text):
        if text[index] in '"\'':
            index = _proto_skip_string(text, index)
            continue
        if text.startswith('/*', index):
            end = text.find('*/', index + 2)
            index = len(text) if end < 0 else end + 2
            continue
        if text.startswith('//', index):
            end = text.find('\n', index)
            index = len(text) if end < 0 else end
            continue
        match = pattern.match(text, index)
        if match is None:
            index += 1
            continue
        line_start = text.rfind('\n', 0, index) + 1
        if text[line_start:index].lstrip().startswith('#'):
            index = match.end()
            continue
        pieces.append(text[cursor:index])
        pieces.append(macros[match.group(1)])
        cursor = match.end()
        index = match.end()
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return ''.join(pieces)


def _expand_function_decl_macros(text: str, macros: dict[str, tuple[list[str], str]]) -> str:
    if not macros:
        return text
    pattern = re.compile(
        r'(?<![\w#])(' + '|'.join(re.escape(name) for name in macros) + r')\s*\('
    )
    pieces: list[str] = []
    cursor = 0
    for match in pattern.finditer(text):
        if match.start() < cursor:
            continue
        line_start = text.rfind('\n', 0, match.start()) + 1
        if text[line_start:match.start()].lstrip().startswith('#'):
            continue
        paren = match.end() - 1
        end = _proto_match(text, paren, '(', ')')
        if end < 0:
            continue
        args = _macro_call_args(text[paren + 1:end])
        params, body = macros[match.group(1)]
        if args is None or len(args) != len(params):
            continue
        index = end + 1
        while index < len(text) and text[index].isspace():
            index += 1
        opens_params = any(
            re.search(rf'(?<![\w]){re.escape(param)}\s*\(', body) is not None
            for param in params
        )
        if index < len(text) and text[index] == '(' and opens_params:
            continue
        expanded = body
        for param, arg in sorted(zip(params, args), key=lambda item: len(item[0]), reverse=True):
            expanded = _substitute_macro_param(expanded, param, arg)
        pieces.append(text[cursor:match.start()])
        pieces.append(expanded)
        cursor = end + 1
    if not pieces:
        return text
    pieces.append(text[cursor:])
    return ''.join(pieces)


def _nearby_source_roots(path: Path) -> list[str]:
    current = path.parent
    for _step in range(6):
        if (
            (current / 'main' / 'php.h').is_file()
            or (current / 'src' / 'core' / 'ngx_config.h').is_file()
            or (current / 'include' / 'httpd.h').is_file()
            or (current / 'c' / 'include' / 'brotli' / 'decode.h').is_file()
        ):
            return [str(current)]
        if current.parent == current:
            break
        current = current.parent
    return []


_HEADER_FILE_INDEX: dict[str, dict[str, str | None]] = {}


def _header_file(root: str, name: str) -> str | None:
    cached = _HEADER_FILE_INDEX.get(root)
    if cached is None:
        buckets: dict[str, list[str]] = {}
        base = Path(root)
        if base.is_dir():
            for path in base.rglob('*'):
                if not path.is_file() or path.suffix.lower() not in {'.h', '.hpp', '.inc'}:
                    continue
                buckets.setdefault(path.name, []).append(str(path))
                rel = path.relative_to(base).as_posix()
                if rel != path.name:
                    buckets.setdefault(rel, []).append(str(path))
        cached = {key: (paths[0] if len(paths) == 1 else None) for key, paths in buckets.items()}
        _HEADER_FILE_INDEX[root] = cached
    return cached.get(name)


def _direct_includes(source: str) -> list[str]:
    names: list[str] = []
    for line in source.splitlines():
        stripped = line.strip()
        if not stripped.startswith('#include'):
            continue
        match = re.search(r'[<"]([^>"]+)[>"]', stripped)
        if match and match.group(1) not in names:
            names.append(match.group(1))
    return names


def _follow_decl_headers(source: str, roots: list[str], limit: int = 128) -> list[str]:
    texts: list[str] = []
    seen: set[str] = set()
    pending = [source]
    while pending and len(texts) < limit:
        current = pending.pop(0)
        for name in _direct_includes(current):
            if len(texts) >= limit:
                break
            path = next((found for root in roots if (found := _header_file(root, name))), None)
            if path is None or path in seen:
                continue
            seen.add(path)
            if 'win32' in Path(path).parts:
                continue
            try:
                text = Path(path).read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            texts.append(text)
            pending.append(text)
    return texts


def _decl_macro_texts(path: Path, text: str) -> list[str]:
    texts = [text]
    if path.parent.is_dir():
        for header in sorted(path.parent.glob('*.h')):
            try:
                texts.append(header.read_text(encoding='utf-8', errors='replace'))
            except OSError:
                continue
    roots = _nearby_source_roots(path)
    if roots and re.search(r'(?m)^[ \t]*#[ \t]*include\b', text):
        texts.extend(_follow_decl_headers(text, roots))
    return texts


def _expand_with_maps(text: str,
                      functions: dict[str, tuple[list[str], str]],
                      objects: dict[str, str]) -> str:
    if not functions and not objects:
        return text
    current = text
    for _step in range(6):
        updated = _expand_object_decl_macros(current, objects)
        updated = _expand_function_decl_macros(updated, functions)
        if updated == current:
            return current
        current = updated
    return current


def _expand_local_decl_macros(text: str) -> str:
    return _expand_with_maps(text, _macros_in_text(text), _object_decl_macros(text))


def _expand_definition_macros(path: Path, text: str) -> str:
    functions: dict[str, tuple[list[str], str]] = {}
    objects: dict[str, str] = {}
    for source in _decl_macro_texts(path, text):
        functions.update(_macros_in_text(source))
        objects.update(_object_decl_macros(source))
    return _expand_with_maps(text, functions, objects)


def _family_preamble(family: str) -> str:
    if family == 'nginx':
        return '#include <ngx_config.h>\n#include <ngx_core.h>\n#include <ngx_http.h>\n'
    if family == 'httpd':
        return '#include <httpd.h>\n#include <http_protocol.h>\n'
    if family == 'php':
        return '#include "php.h"\n'
    if family == 'brotli':
        return '#include <brotli/decode.h>\n#include "state.h"\n'
    return ''


def _function_pointer_binding(item: dict[str, Any], owner: str) -> tuple[str, str, str]:
    name = str(item['name'])
    stub = f'__vg_fp_{owner}_{name}'
    ret = str(item['type_text'])
    args = str(item['args_text'])
    if item.get('callback_array_dims'):
        shown = ''.join(f'[{int(size)}]' for size in item['callback_array_dims'])
        slot = ''.join('[0]' for _size in item['callback_array_dims'])
        body = '    __vulgate_missing_callee_hit = 1;'
        if ret != 'void':
            body += '\n    return 0;'
        source = f'static {ret} {stub}({args}) {{\n{body}\n}}'
        local = (
            f'    {ret} (*{name}_fp{shown})({args});\n'
            f'    memset({name}_fp, 0, sizeof({name}_fp));\n'
            f'    {name}_fp{slot} = {stub};'
        )
        return source, local, f'{name}_fp'
    wrapped = item.get('callback_return_dims') or item.get('callback_return_args') or item.get('callback_mid_args')
    layers = [str(part) for part in (item.get('callback_layer_args') or [])]
    if item.get('callback_mid_args') and not layers:
        layers = [str(item['callback_mid_args'])]
    if layers:
        args = str(item['args_text'])
        suffix = ''.join(f'[{int(size)}]' for size in item['callback_return_dims']) if item.get('callback_return_dims') else f'({item.get("callback_return_args")})'
        body = '    __vulgate_missing_callee_hit = 1;\n    return 0;'
        source = 'static ' + _wrap_callback_core(ret, f'{stub}({args})', layers, suffix) + ' {\n' + body + '\n}'
        local = '    ' + _wrap_callback_core(ret, f'(*{name}_fp)({args})', layers, suffix) + f' = {stub};'
        return source, local, f'{name}_fp'
    if wrapped:
        signature = {
            'return_pointee': ret,
            'return_stars': str(item.get('callback_return_stars') or '*'),
            'return_array_dims': item.get('callback_return_dims'),
            'return_callback_args': str(item.get('callback_return_args') or ''),
            'return_decl': ret,
            'return_type': ret,
        }
        body = '    __vulgate_missing_callee_hit = 1;\n    return 0;'
        source = 'static ' + _function_declarator(signature, stub, args) + ' {\n' + body + '\n}'
        stars = str(item.get('callback_stars') or '*')
        joiner = '' if stars.endswith('*') else ' '
        suffix = ''.join(f'[{int(size)}]' for size in item['callback_return_dims']) if item.get('callback_return_dims') else f'({item.get("callback_return_args")})'
        local = f'    {ret} (*({stars}{joiner}{name}_fp)({args})){suffix} = {stub};'
        return source, local, f'{name}_fp'
    if item.get('returns_aggregate'):
        body = (
            '    __vulgate_missing_callee_hit = 1;\n'
            f'    {ret} __vg_fp_ret;\n'
            '    memset(&__vg_fp_ret, 0, sizeof(__vg_fp_ret));\n'
            '    return __vg_fp_ret;'
        )
    else:
        body = '    __vulgate_missing_callee_hit = 1;'
        if ret != 'void':
            body += '\n    return 0;'
    source = f'static {ret} {stub}({args}) {{\n{body}\n}}'
    local = f'    {ret} (*{name}_fp)({args}) = {stub};'
    return source, local, f'{name}_fp'


def _address_callback(item: dict[str, Any], name: str, argument: str, rows: list[str]) -> str:
    depth = int(item.get('callback_address_depth') or 0)
    if depth <= 0:
        return argument
    current = argument
    ret = str(item['type_text'])
    args = str(item['args_text'])
    for level in range(1, depth):
        pointer = f'{name}_fp_ptr' if level == 1 else f'{name}_fp_ptr{level}'
        stars = '*' * (level + 1)
        rows.append(f'    {ret} ({stars}{pointer})({args}) = &{current};')
        current = pointer
    return f'&{current}'


def _pointer_to_array_param(text: str, index: int) -> dict[str, Any] | None:
    match = re.fullmatch(
        r'(?P<type>.+?)\s*\(\s*(?P<stars>.*?)\s*(?P<name>[A-Za-z_]\w*)\s*\)\s*(?P<dims>(?:\[\s*\d*\s*\])+)\s*',
        text.strip(),
    )
    if match is None:
        return None
    stars = ' '.join(match.group('stars').split())
    if not stars or not re.fullmatch(r'(?:\*|const|volatile|restrict|\s)+', stars):
        return None
    star_count = stars.count('*')
    if star_count < 1 or star_count > 9:
        return None
    name = match.group('name')
    if name in _PROTO_INTEGER_WORDS or name in {'struct', 'union', 'enum'}:
        return None
    raw_type = ' '.join(match.group('type').split())
    if any(char in raw_type for char in '()[]'):
        return None
    cleaned = ' '.join(_clean_type_text(raw_type).split())
    if not cleaned or not re.fullmatch(
        r'(?:(?:const|struct|union|enum|unsigned|signed|long|short|int|char|void)\s+)*[A-Za-z_]\w*(?:\s*\*)*',
        cleaned,
    ):
        return None
    dims: list[int] = []
    for dim in re.finditer(r'\[\s*(\d*)\s*\]', match.group('dims')):
        length = dim.group(1)
        size = int(length) if length else 16
        dims.append(size if size > 0 else 16)
    if not dims:
        return None
    pointee = ' '.join(cleaned.replace('*', ' ').split())
    shown = ''.join(f'[{size}]' for size in dims)
    joiner = '' if stars.endswith('*') else ' '
    return {
        'kind': 'pointer',
        'name': name,
        'type_text': cleaned,
        'decl_type': f'{cleaned} ({stars}{joiner}{name}){shown}',
        'pointee': pointee,
        'array_len': dims[0],
        'array_dims': dims,
        'array_pointer_depth': star_count,
        'index': index,
    }


def _array_pointer_storage(item: dict[str, Any], local: str) -> tuple[list[str], str]:
    shown = ''.join(f'[{int(size)}]' for size in item['array_dims'])
    rows = [
        f'    {item["pointee"]} {local}{shown};',
        f'    memset({local}, 0, sizeof({local}));',
    ]
    depth = int(item.get('array_pointer_depth') or 1)
    if depth < 2:
        return rows, f'&{local}'
    current = local
    for level in range(1, depth):
        pointer = f'{local}_ptr' if level == 1 else f'{local}_ptr{level}'
        stars = '*' * level
        rows.append(f'    {item["pointee"]} ({stars}{pointer}){shown};')
        rows.append(f'    {pointer} = &{current};')
        current = pointer
    return rows, f'&{current}'


def _param_decl(item: dict[str, Any]) -> str:
    if item.get('value_array_dims'):
        shown = ''.join(f'[{int(size)}]' for size in item['value_array_dims'])
        return f'{item["pointee"]} {item["name"]}{shown}'
    if item['kind'] == 'function_pointer' or item.get('array_dims'):
        return str(item['decl_type'])
    if item['kind'] == 'buffer' and item.get('array_len'):
        return f'{item["pointee"]} {item["name"]}[{int(item["array_len"])}]'
    shown = str(item.get('decl_type') or item.get('type_text') or '')
    if item['kind'] == 'buffer' and shown.count('*') <= 1:
        return f'void *{item["name"]}'
    return f'{shown} {item["name"]}'


def _is_brigade_pointer(item: dict[str, Any]) -> bool:
    if item.get('kind') != 'pointer':
        return False
    text = ' '.join(str(item.get(key) or '') for key in ('type_text', 'decl_type', 'pointee'))
    return 'bucket_brigade' in text and str(item.get('type_text') or '').count('*') <= 1


def _brigade_setup(name: str) -> tuple[list[str], str]:
    pool = f'{name}_pool'
    alloc = f'{name}_alloc'
    local = f'{name}_obj'
    return [
        f'    apr_pool_t {pool};',
        f'    memset(&{pool}, 0, sizeof({pool}));',
        f'    apr_bucket_alloc_t *{alloc} = apr_bucket_alloc_create(&{pool});',
        f'    apr_bucket_brigade *{local} = apr_brigade_create(&{pool}, {alloc});',
    ], local


def _function_declarator(signature: dict[str, Any], name: str, params_text: str) -> str:
    dims = signature.get('return_array_dims')
    callback = str(signature.get('return_callback_args') or '')
    joined = params_text or 'void'
    if dims or callback:
        pointee = str(signature.get('return_pointee') or signature['return_type'])
        stars = str(signature.get('return_stars') or '*')
        joiner = '' if stars.endswith('*') else ' '
        wrapped = f'{pointee} ({stars}{joiner}{name}({joined}))'
        if dims:
            shown = ''.join(f'[{int(size)}]' for size in dims)
            return wrapped + shown
        return wrapped + f'({callback})'
    shown = str(signature.get('return_decl') or signature['return_type'])
    return f'{shown} {name}({joined})'


def _result_lines(return_type: str, call: str, dest: str, aggregate: bool, local: str,
                  array_dims: list[int] | None = None, return_stars: str = '',
                  pointee: str = '', callback_args: str = '') -> str:
    if array_dims or callback_args:
        stars = return_stars or '*'
        joiner = '' if stars.endswith('*') else ' '
        base = pointee or return_type
        wrapped = f'{base} ({stars}{joiner}{local})'
        if array_dims:
            shown = ''.join(f'[{int(size)}]' for size in array_dims)
            wrapped += shown
        else:
            wrapped += f'({callback_args})'
        return (
            f'    {wrapped} = {call};\n'
            f'    {dest} = (uint64_t)(uintptr_t){local};'
        )
    if aggregate:
        return (
            f'    {return_type} {local};\n'
            f'    memset(&{local}, 0, sizeof({local}));\n'
            f'    {local} = {call};\n'
            f'    {dest} = 0;'
        )
    if return_type == 'void':
        return f'    {call};\n    {dest} = 0;'
    return (
        f'    {return_type} {local} = {call};\n'
        f'    {dest} = (uint64_t)(uintptr_t){local};'
    )


def _brigade_checks(names: list[str]) -> str:
    if not names:
        return ''
    return '\n' + '\n'.join(
        f'    __CPROVER_assert(__vg_brigade_consistent({name}), "vg.obligation.brigade_ring");'
        for name in names
    )


def _pointer_storage(item: dict[str, Any], local: str) -> tuple[list[str], str]:
    shown = str(item.get('decl_type') or item['type_text'])
    depth = shown.count('*')
    pointee = ' '.join(word for word in shown.replace('*', ' ').split() if word != 'const')
    if depth <= 1:
        return [
            f'    {pointee} {local};',
            f'    memset(&{local}, 0, sizeof({local}));',
        ], f'&{local}'
    stars = '* ' * (depth - 1)
    return [
        f'    {pointee} {stars}{local};',
        f'    {local} = 0;',
    ], f'&{local}'


def _note_anonymous(sym_scope: dict[str, Any], signatures: list[dict[str, Any]]) -> None:
    fresh = [item for item in signatures if item.get('anonymous_types')]
    if not fresh:
        return
    stored = [item for item in (sym_scope.get('anonymous_signatures') or []) if isinstance(item, dict)]
    known = {str(item.get('name') or '') for item in stored}
    for item in fresh:
        name = str(item.get('name') or '')
        if name in known:
            continue
        stored.append(item)
        known.add(name)
    sym_scope['anonymous_signatures'] = stored


def render_prototype_driver(family: str,
                            signature: dict[str, Any],
                            sym_scope: dict[str, Any]) -> str:
    _note_anonymous(sym_scope, [signature])
    parameters = list(signature['parameters'])
    return_type = str(signature['return_type'])
    return_decl = str(signature.get('return_decl') or return_type)
    function = str(signature.get('call_name') or signature['name'])
    bounds = sym_scope.get('input_bounds') or {}
    decl_params = _declaration_params(signature)
    runner = (sym_scope.get('hook_runners') or {}).get(str(signature['name']))
    if runner:
        declaration = str(runner)
    else:
        declaration = _function_declarator(
            signature, function, ', '.join(decl_params) if decl_params else 'void',
        ) + ';'
    seed_decls, seed_sigs = _opcode_declarations(sym_scope, [str(signature['name'])])
    link_decls: list[str] = []
    for link in sym_scope.get('slot_links') or []:
        if family not in {'nginx', 'httpd'}:
            target_sig = link['target_signature']
            link_params = ', '.join(_param_decl(item) for item in target_sig['parameters']) or 'void'
            link_return = str(target_sig.get('return_decl') or target_sig['return_type'])
            link_decls.append(f'extern {link_return} (*{link["slot"]})({link_params});')
        link_decls.append(str(link['callee_decl']))
    if link_decls:
        declaration = '\n'.join(link_decls) + '\n' + declaration
    handler_decls = [str(item) for item in sym_scope.get('handler_decls') or [] if str(item).strip()]
    if handler_decls:
        declaration = '\n'.join(handler_decls) + '\n' + declaration
    if seed_decls:
        declaration = '\n'.join(seed_decls) + '\n' + declaration
    integers = [item for item in parameters if item['kind'] == 'integer']
    brigade_names: list[str] = []
    function_stubs: list[str] = []
    world_params = ', '.join(f'uint64_t __vg_in_{item["name"]}' for item in integers)
    if world_params:
        world_params += ', '
    locals: list[str] = [
        f'    {link["slot"]} = {link["target"]};'
        for link in sym_scope.get('slot_links') or []
    ]
    arguments: list[str] = []
    for item in parameters:
        name = item['name']
        if item['kind'] == 'integer':
            arguments.append(f'(({item["type_text"]})__vg_in_{name})')
            continue
        if item['kind'] == 'function_pointer':
            stub, local, argument = _function_pointer_binding(item, function)
            function_stubs.append(stub)
            locals.append(local)
            arguments.append(_address_callback(item, name, argument, locals))
            continue
        if item.get('value_array_dims'):
            local = f'{name}_obj'
            shown = ''.join(f'[{int(size)}]' for size in item['value_array_dims'])
            locals.append(f'    {item["pointee"]} {local}{shown};')
            locals.append(f'    memset({local}, 0, sizeof({local}));')
            arguments.append(local)
            continue
        if item.get('array_dims'):
            local = f'{name}_obj'
            stored, argument = _array_pointer_storage(item, local)
            locals.extend(stored)
            arguments.append(argument)
            continue
        if item['kind'] == 'buffer' and item.get('array_len'):
            local = f'{name}_obj'
            locals.append(f'    {item["pointee"]} {local}[{int(item["array_len"])}];')
            locals.append(f'    memset({local}, 0, sizeof({local}));')
            arguments.append(local)
            continue
        if item['kind'] == 'buffer' and str(item.get('decl_type') or '').count('*') > 1:
            local = f'{name}_obj'
            stored, argument = _pointer_storage(item, local)
            locals.extend(stored)
            arguments.append(argument)
            continue
        if item['kind'] == 'buffer':
            local = f'{name}_obj'
            bare = _bare_code_slot(sym_scope, str(signature['name']), name)
            if bare is not None:
                locals.extend(_code_word_lines(local, bare.get('opcode')))
            else:
                locals.append(f'    uint8_t {local}[16];')
                locals.append(f'    memset({local}, 0, sizeof({local}));')
            arguments.append(local)
            continue
        if item['kind'] == 'struct_value':
            local = f'{name}_obj'
            locals.append(f'    {item["type_text"]} {local};')
            locals.append(f'    memset(&{local}, 0, sizeof({local}));')
            locals.extend(_field_code_lines(sym_scope, str(signature['name']), name, local))
            arguments.append(local)
            continue
        if _is_brigade_pointer(item):
            setup, local = _brigade_setup(name)
            locals.extend(setup)
            arguments.append(local)
            brigade_names.append(local)
            continue
        local = f'{name}_obj'
        stored, argument = _pointer_storage(item, local)
        locals.extend(stored)
        locals.extend(_field_code_lines(sym_scope, str(signature['name']), name, local))
        arguments.append(argument)
    if function_stubs:
        declaration = 'extern _Bool __vulgate_missing_callee_hit;\n' + '\n'.join(function_stubs) + '\n' + declaration
    call = _result_lines(
        return_type,
        f'{function}({", ".join(arguments)})',
        'obs->status_code',
        bool(signature.get('returns_aggregate')),
        'vg_ret',
        signature.get('return_array_dims'),
        str(signature.get('return_stars') or ''),
        str(signature.get('return_pointee') or ''),
        str(signature.get('return_callback_args') or ''),
    )
    seed_groups = [list(group) for group in (sym_scope.get('handler_seeds') or [])]
    if seed_groups:
        blocks: list[str] = []
        for group in seed_groups:
            rows = [str(line) for line in group if str(line).strip()]
            if len(seed_groups) > 1:
                inner = '\n'.join('    ' + line for line in call.splitlines())
                chunk = '\n'.join(rows + ['    {', inner, '    }'])
            else:
                chunk = '\n'.join(rows + [call])
            blocks.append(chunk)
        call = '\n'.join(blocks)
    call += _brigade_checks(brigade_names)
    entry_params = f'{world_params}vg_proto_obs *obs'
    assumes = []
    for item in integers:
        spec = bounds.get(item['name']) or {}
        low = int(spec.get('min', 0))
        high = int(spec.get('max', 16))
        assumes.append(
            f'    __CPROVER_assume(__vg_in_{item["name"]} >= {low}ULL && __vg_in_{item["name"]} <= {high}ULL);'
        )
    assume_text = '\n'.join(assumes)
    input_decls = '\n'.join(
        f'    uint64_t __vg_in_{item["name"]} = __vulgate_nondet_u64();' for item in integers
    )
    input_args = ', '.join(f'__vg_in_{item["name"]}' for item in integers)
    if input_args:
        input_args += ', '
    dispatch_parts = [
        str(item.get('includes') or '') + str(item.get('source') or '')
        for item in sym_scope.get('field_dispatches') or []
    ]
    dispatch_text = '\n'.join(part for part in dispatch_parts if part)
    if dispatch_text:
        dispatch_text += '\n'
    model = HTTPD_ENV_MODEL + '\n' if brigade_names else ''
    return f'''{_family_preamble(family)}{model}#include <stdint.h>
#include <stddef.h>
#include <string.h>
{_merged_typedef_text([signature, *seed_sigs])}{dispatch_text}{declaration}

typedef struct vg_proto_obs {{
    uint64_t status_code;
}} vg_proto_obs;

static void vg_proto_entry({entry_params}) {{
{chr(10).join(locals)}
{call}
}}

int __vg_run_world_0({entry_params}) {{
    vg_proto_entry({input_args}obs);
    return (int)obs->status_code;
}}
int __vg_run_world_1({entry_params}) {{
    vg_proto_entry({input_args}obs);
    return (int)obs->status_code;
}}

void __vg_verify_obligations(void) {{
{input_decls}
{assume_text}
    vg_proto_obs obs0 = {{0}}, obs1 = {{0}};
    __vg_run_world_0({input_args}&obs0);
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    __vg_run_world_1({input_args}&obs1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}}

void __vg_impact_harness(void) {{
{input_decls}
{assume_text}
    /*VG_IMPACT_REGION_ASSUME*/
    vg_proto_obs obs0 = {{0}}, obs1 = {{0}};
    __vg_run_world_0({input_args}&obs0);
    __vulgate_any_blocked = 0;
    __vg_run_world_1({input_args}&obs1);
    _Bool __vg_obs_diff = (obs0.status_code != obs1.status_code);
    /*VG_IMPACT_QUERY_ASSERT*/
}}
'''


def _defined_functions(source: str) -> list[tuple[str, str, bool]]:
    text = _strip_c_comments(source)
    found: list[tuple[str, str, bool]] = []
    pattern = re.compile(r'(?<![\w#])([A-Za-z_]\w*)\s*\(')
    for match in pattern.finditer(text):
        name = match.group(1)
        if name in {'if', 'for', 'while', 'switch', 'return', 'sizeof', 'defined'}:
            continue
        close = _proto_match(text, match.end() - 1, '(', ')')
        if close < 0:
            continue
        cursor = close + 1
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        while text.startswith('__attribute__', cursor) or text.startswith('__declspec', cursor):
            paren = text.find('(', cursor)
            if paren < 0:
                break
            end = _proto_match(text, paren, '(', ')')
            if end < 0:
                break
            cursor = end + 1
            while cursor < len(text) and text[cursor].isspace():
                cursor += 1
        if cursor >= len(text) or text[cursor] != '{':
            continue
        end = _match_code_brace(text, cursor)
        if end < 0:
            continue
        defined = name
        argument = text[match.end():close].strip()
        if name.isupper() and re.fullmatch(r'[A-Za-z_]\w*', argument):
            defined = argument
        header = text[_header_start(text, match.start()):match.start()]
        found.append((defined, text[cursor + 1:end], bool(re.search(r'\bstatic\b', header))))
    return found


def _body_calls(body: str, name: str) -> bool:
    pattern = re.compile(rf'(?<![\w#]){re.escape(name)}\s*\(')
    index = 0
    while index < len(body):
        if body[index] in '"\'':
            index = _proto_skip_string(body, index)
            continue
        if pattern.match(body, index):
            return True
        index += 1
    return False


_DEFINITION_CACHE: dict[tuple[str, str], str | None] = {}


def _source_root(case_ir: dict[str, Any] | None) -> Path | None:
    builds = ((case_ir or {}).get('app_profile') or {}).get('builds') or {}
    raw = (builds.get('baseline') or {}).get('source_dir')
    if not raw:
        return None
    root = Path(str(raw))
    return root if root.is_dir() else None


def _slice_c_files(case_ir: dict[str, Any] | None,
                   sym_scope: dict[str, Any] | None = None) -> list[Path]:
    raws: list[Any] = []
    if sym_scope is not None:
        raws.extend(list(sym_scope.get('slice_sources') or []))
    case = case_ir or {}
    raws.extend(list((case.get('symbolization_scope') or {}).get('slice_sources') or []))
    raws.extend(list((((case.get('app_profile') or {}).get('symbolic_slice') or {}).get('slice_sources') or [])))
    found: list[Path] = []
    seen: set[str] = set()
    for raw in raws:
        path = Path(str(raw))
        if path.suffix != '.c' or not path.is_file():
            continue
        try:
            key = str(path.resolve())
        except OSError:
            continue
        if key in seen:
            continue
        seen.add(key)
        found.append(path)
    found.sort(key=lambda item: str(item))
    return found


def _function_definition_kind(source: str, function: str) -> str | None:
    if function not in source:
        return None
    return _kind_from_defined(source, function)


def _kind_from_defined(source: str, function: str) -> str | None:
    kind = None
    for name, _body, static in _defined_functions(source):
        if name != function:
            continue
        if not static:
            return 'global'
        kind = 'static'
    return kind


_CAPS_DECL_CALL = re.compile(r'(?<![\w])([A-Z][A-Z0-9_]{2,})\s*\(\s*([A-Za-z_]\w*)\s*\)')
_SHAPE_CACHE: dict[str, list[tuple[str, str, str]]] = {}
_EXPANDED_DEFINED_CACHE: dict[tuple[str, int, int], list[tuple[str, str, bool]]] = {}


def _paste_reachable(name: str,
                     functions: dict[str, tuple[list[str], str]],
                     objects: dict[str, str],
                     seen: set[str]) -> bool:
    if name in seen:
        return False
    seen.add(name)
    if name in objects:
        body = objects[name]
        if '##' in body:
            return True
        target = body.strip()
        if re.fullmatch(r'[A-Za-z_]\w*', target):
            return _paste_reachable(target, functions, objects, seen)
        return False
    if name not in functions:
        return False
    _params, body = functions[name]
    if '##' in body:
        return True
    for called in re.findall(r'\b([A-Z][A-Z0-9_]*)\b', body):
        if called != name and _paste_reachable(called, functions, objects, seen):
            return True
    return False


def _macro_shapes(functions: dict[str, tuple[list[str], str]],
                  objects: dict[str, str]) -> list[tuple[str, str, str]]:
    if not functions and not objects:
        return []
    names: list[str] = []
    for name, (params, _body) in functions.items():
        if len(params) == 1 and _paste_reachable(name, functions, objects, set()):
            names.append(name)
    for name, body in objects.items():
        target = body.strip()
        if (
            re.fullmatch(r'[A-Za-z_]\w*', target)
            and target in functions
            and len(functions[target][0]) == 1
            and _paste_reachable(target, functions, objects, set())
        ):
            names.append(name)
    shapes: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    for name in names:
        sample = f'{name}(__vg_arg__) {{}}\n'
        expanded = _expand_with_maps(sample, functions, objects)
        for defined, _body, _static in _defined_functions(expanded):
            token = '__vg_arg__'
            if token not in defined:
                continue
            prefix, suffix = defined.split(token, 1)
            if not prefix and not suffix:
                continue
            item = (name, prefix, suffix)
            if item in seen:
                continue
            seen.add(item)
            shapes.append(item)
    return shapes


def _header_definition_shapes(root: Path) -> list[tuple[str, str, str]]:
    key = str(root.resolve()) if root.exists() else str(root)
    cached = _SHAPE_CACHE.get(key)
    if cached is not None:
        return cached
    functions: dict[str, tuple[list[str], str]] = {}
    objects: dict[str, str] = {}
    if root.is_dir():
        for path in root.rglob('*'):
            if not path.is_file() or path.suffix.lower() not in {'.h', '.hpp', '.inc'}:
                continue
            if 'win32' in path.parts:
                continue
            try:
                text = path.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            functions.update(_macros_in_text(text))
            objects.update(_object_decl_macros(text))
    shapes = _macro_shapes(functions, objects)
    _SHAPE_CACHE[key] = shapes
    return shapes


def _macro_call_defines(text: str, function: str, shapes: list[tuple[str, str, str]]) -> bool:
    for macro, prefix, suffix in shapes:
        if prefix and not function.startswith(prefix):
            continue
        if suffix and not function.endswith(suffix):
            continue
        end = len(function) - len(suffix) if suffix else len(function)
        middle = function[len(prefix):end]
        if not middle or not re.fullmatch(r'[A-Za-z_]\w*', middle):
            continue
        if re.search(
            rf'(?<![\w]){re.escape(macro)}\s*\(\s*{re.escape(middle)}\s*\)',
            text,
        ):
            return True
    return False


def _confirmed_kind(path: Path, text: str, function: str, kind: str | None) -> str | None:
    if not kind:
        return None
    if '#define' not in text and _CAPS_DECL_CALL.search(text) is None:
        return kind
    return _kind_from_defined(_expand_definition_macros(path, text), function)


def _expanded_defined_functions(path: Path) -> list[tuple[str, str, bool]]:
    try:
        stat = path.stat()
    except OSError:
        return []
    key = (str(path.resolve()), stat.st_mtime_ns, stat.st_size)
    cached = _EXPANDED_DEFINED_CACHE.get(key)
    if cached is not None:
        return cached
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        _EXPANDED_DEFINED_CACHE[key] = []
        return []
    found = _defined_functions(_expand_definition_macros(path, text))
    _EXPANDED_DEFINED_CACHE[key] = found
    return found


def locate_function_source(source_dir: str | Path,
                           function: str,
                           anchors: list[Path] | None = None) -> Path | None:
    root = Path(source_dir)
    key = (str(root.resolve()) if root.exists() else str(root), function)
    if key in _DEFINITION_CACHE:
        cached = _DEFINITION_CACHE[key]
        return Path(cached) if cached else None
    candidates: list[Path] = []
    seen: set[Path] = set()
    for path in anchors or []:
        resolved = path.resolve() if path.exists() else path
        if resolved in seen or not path.is_file():
            continue
        seen.add(resolved)
        candidates.append(path)
    if root.is_dir():
        for path in sorted(root.rglob('*.c')):
            if not path.is_file():
                continue
            resolved = path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            candidates.append(path)
    matches: list[tuple[str, Path]] = []
    macro_candidates: list[Path] = []
    shapes: list[tuple[str, str, str]] | None = None
    for path in candidates:
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        kind = _confirmed_kind(path, text, function, _function_definition_kind(text, function))
        if kind:
            matches.append((kind, path))
            continue
        local_functions = _macros_in_text(text)
        local_objects = _object_decl_macros(text) if local_functions else {}
        local_shapes = _macro_shapes(local_functions, local_objects)
        if local_shapes and _macro_call_defines(text, function, local_shapes):
            macro_candidates.append(path)
            continue
        if shapes is None and any(
            match.group(1) not in local_functions for match in _CAPS_DECL_CALL.finditer(text)
        ):
            shapes = _header_definition_shapes(root)
        if shapes and _macro_call_defines(text, function, shapes):
            macro_candidates.append(path)
    if not matches:
        for path in macro_candidates:
            try:
                text = path.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            kind = _kind_from_defined(_expand_definition_macros(path, text), function)
            if kind:
                matches.append((kind, path))
    if not matches:
        _DEFINITION_CACHE[key] = None
        return None

    def rank(item: tuple[str, Path]) -> tuple[int, int, int, str]:
        kind, path = item
        return (
            0 if kind == 'global' else 1,
            0 if function in path.name else 1,
            len(str(path)),
            str(path),
        )

    chosen = sorted(matches, key=rank)[0][1]
    _DEFINITION_CACHE[key] = str(chosen.resolve())
    return chosen


_CALLEE_SKIP = {
    'if', 'for', 'while', 'do', 'switch', 'return', 'sizeof', 'offsetof',
    'defined', 'typeof', 'alignof', 'static_assert',
    'ngx_palloc', 'ngx_pnalloc', 'ngx_pcalloc', 'ngx_pfree',
    'ngx_log_error', 'ngx_log_error_core', 'ngx_log_debug', 'ngx_log_debug_core',
    'ngx_log_stderr', 'ngx_write_stderr', 'ngx_log_errno',
    'apr_palloc', 'apr_pcalloc', 'apr_brigade_create', 'apr_brigade_destroy',
    'apr_brigade_cleanup', 'apr_bucket_alloc_create', 'apr_bucket_alloc_destroy',
    'apr_bucket_alloc', 'apr_bucket_free',
    'ap_log_rerror', 'ap_log_rerror_', 'ap_log_cerror', 'ap_log_cerror_',
    'ap_log_error', 'ap_log_error_', 'ap_log_perror', 'ap_log_perror_',
    '_emalloc', '_safe_emalloc', '_ecalloc', '_efree', '_zend_bailout',
    'php_error_docref', 'zend_error',
}

_CALLEE_SKIP_PREFIXES = ('ngx_log_', 'ap_log_')
_ENV_MODELED_CALLEE_FILES = frozenset({
    'ngx_log.c', 'ngx_palloc.c', 'ngx_alloc.c',
    'apr_pools.c', 'zend_alloc.c',
})


def _function_body_at(path: Path, function: str) -> str | None:
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None
    expanded = _expand_definition_macros(path, text)
    for item_name, item_body, _static in _defined_functions(expanded):
        if item_name == function:
            return item_body
    return None


def guard_callee_files(case_ir: dict[str, Any], names: list[str], hops: int = 2) -> list[Path]:
    root = _source_root(case_ir)
    if root is None:
        return []
    found: list[Path] = []
    seen_files: set[Path] = set()
    seen_functions: set[str] = set()
    own_files: set[Path] = set()
    queue: list[tuple[str, int]] = [(str(name), 0) for name in names if name]
    while queue:
        function, depth = queue.pop(0)
        if function in seen_functions or depth > hops:
            continue
        seen_functions.add(function)
        path = locate_function_source(root, function)
        if path is None or not path.is_file():
            continue
        if depth == 0:
            own_files.add(path.resolve())
        if depth >= hops:
            continue
        body = _function_body_at(path, function)
        if body is None:
            continue
        calls = re.findall(r'(?<![\w])([A-Za-z_]\w*)\s*\(', body)
        for callee in sorted(set(calls)):
            if callee in _CALLEE_SKIP or callee == function or callee.startswith('__') or callee.startswith(_CALLEE_SKIP_PREFIXES):
                continue
            callee_path = locate_function_source(root, callee)
            if callee_path is None or not callee_path.is_file() or callee_path.name in _ENV_MODELED_CALLEE_FILES:
                continue
            try:
                callee_text = callee_path.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            kind = _function_definition_kind(callee_text, callee)
            if kind is None:
                kind = _kind_from_defined(
                    _expand_definition_macros(callee_path, callee_text),
                    callee,
                )
            if kind != 'global':
                continue
            resolved = callee_path.resolve()
            if resolved not in own_files and resolved not in seen_files:
                seen_files.add(resolved)
                found.append(resolved)
            if depth + 1 < hops:
                queue.append((callee, depth + 1))
    return found


def _handler_suffix(function: str) -> str:
    parts = function.split('_')
    if len(parts) >= 3:
        return '_'.join(parts[2:])
    return function


def discovered_unhooked_entries(case_ir: dict[str, Any], names: list[str]) -> list[str]:
    root = _source_root(case_ir)
    if root is None:
        return []
    found: list[str] = []
    seen: set[str] = set()

    def add(name: str) -> None:
        if name and name not in seen:
            seen.add(name)
            found.append(name)

    assign_cache: dict[str, list[str]] | None = None

    def assignments(field: str) -> list[str]:
        nonlocal assign_cache
        if assign_cache is None:
            assign_cache = {}
            pattern = re.compile(r'(?:->|\.)\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;')
            for item in sorted(root.rglob('*.c')):
                try:
                    raw = item.read_text(encoding='utf-8', errors='replace')
                except OSError:
                    continue
                for stored, target in pattern.findall(raw):
                    assign_cache.setdefault(stored, [])
                    if target not in assign_cache[stored]:
                        assign_cache[stored].append(target)
        return assign_cache.get(field, [])

    for name in names:
        path = locate_function_source(root, name)
        if path is None or not path.is_file():
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        fields = _stored_fields(text, name)
        suffix = _handler_suffix(name)
        if len(fields) == 1 and suffix:
            for other in assignments(fields[0]):
                if other == name:
                    continue
                if other == suffix or other.endswith('_' + suffix):
                    add(other)
        body = _function_body_at(path, name)
        if body is None:
            continue
        calls = re.findall(r'(?<![\w])([A-Za-z_]\w*)\s*\(', body)
        for callee in sorted(set(calls)):
            if callee in _CALLEE_SKIP or callee == name or callee.startswith('__'):
                continue
            callee_path = locate_function_source(root, callee)
            if callee_path is None or not callee_path.is_file():
                continue
            callee_body = _function_body_at(callee_path, callee)
            if callee_body is None or not re.search(r'->\s*lengths\s*==\s*NULL', callee_body):
                continue
            try:
                callee_text = callee_path.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            defined = {
                item_name: item_body
                for item_name, item_body, _static in _defined_functions(
                    _expand_definition_macros(callee_path, callee_text)
                )
            }
            for called in re.findall(r'(?<![\w])([A-Za-z_]\w*)\s*\(', callee_body):
                other_body = defined.get(called)
                if other_body and re.search(r'(?<![\w])no_cacheable(?![\w])', other_body):
                    add(f'{callee}_noncacheable')
                    break
        plan = _handler_field_plan(path, text, name, case_ir)
        if plan and any('__vg_indexed_other' in line for line in plan.get('setup') or []):
            add('__vg_indexed_other')
    return found


def _call_graph(path: Path, text: str) -> dict[str, list[str]]:
    expanded = _expand_definition_macros(path, text)
    defined = {
        name: body
        for name, body, _static in _defined_functions(expanded)
    }
    graph: dict[str, list[str]] = {}
    for name, body in defined.items():
        calls: list[str] = []
        for called in re.findall(r'(?<![\w])([A-Za-z_]\w*)\s*\(', body):
            if called in _CALLEE_SKIP or called == name or called not in defined or called in calls:
                continue
            calls.append(called)
        graph[name] = calls
    return graph


def _registered_filters(text: str) -> tuple[list[str], list[str]]:
    stripped = _strip_c_comments(text)
    inputs = list(dict.fromkeys(re.findall(
        r'(?<![\w])ap_register_input_filter(?:_protocol)?\s*\(\s*[^,]*,\s*([A-Za-z_]\w*)',
        stripped,
    )))
    outputs = list(dict.fromkeys(re.findall(
        r'(?<![\w])ap_register_output_filter(?:_protocol)?\s*\(\s*[^,]*,\s*([A-Za-z_]\w*)',
        stripped,
    )))
    return inputs, outputs


def _shortest_avoiding(graph: dict[str, list[str]],
                       entry: str,
                       sinks: set[str],
                       guards: set[str]) -> list[str] | None:
    queue: deque[list[str]] = deque([[entry]])
    seen = {entry}
    while queue:
        path = queue.popleft()
        for nxt in graph.get(path[-1], []):
            if nxt in guards or nxt in seen:
                continue
            nxt_path = [*path, nxt]
            if nxt in sinks:
                return nxt_path
            seen.add(nxt)
            queue.append(nxt_path)
    return None


def source_bypass_chains(case_ir: dict[str, Any],
                         guard_names: list[str],
                         sink_names: list[str]) -> list[list[str]]:
    root = _source_root(case_ir)
    declared = [str(name) for name in sink_names if name]
    if root is None or not declared or not guard_names:
        return []
    guards = {str(name) for name in guard_names if name}
    rels: list[str] = []
    anchors = case_ir.get('defect_anchors') or {}
    for key in ('sink_site', 'root_cause_site'):
        rel = (anchors.get(key) or {}).get('file')
        if rel:
            rels.append(str(rel))
    for guard in case_ir.get('guards') or []:
        rel = guard.get('source_file')
        if rel:
            rels.append(str(rel))
    files: list[Path] = []
    seen_files: set[Path] = set()
    for rel in rels:
        path = root / rel
        if not path.is_file():
            continue
        resolved = path.resolve()
        if resolved in seen_files:
            continue
        seen_files.add(resolved)
        files.append(path)
    covered: set[str] = set()
    sources: list[tuple[Path, str]] = []
    for path in files:
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        sources.append((path, text))
        for name in guards:
            if _function_definition_kind(text, name):
                covered.add(name)
    for name in guards - covered:
        path = locate_function_source(root, name)
        if path is None or not path.is_file():
            continue
        resolved = path.resolve()
        if resolved in seen_files:
            continue
        seen_files.add(resolved)
        try:
            sources.append((path, path.read_text(encoding='utf-8', errors='replace')))
        except OSError:
            continue
    if not sources:
        return []
    graph: dict[str, list[str]] = {}
    inputs: list[str] = []
    outputs: list[str] = []
    for path, text in sources:
        for name, calls in _call_graph(path, text).items():
            graph.setdefault(name, [])
            for called in calls:
                if called not in graph[name]:
                    graph[name].append(called)
        file_inputs, file_outputs = _registered_filters(text)
        for name in file_inputs:
            if name not in inputs:
                inputs.append(name)
        for name in file_outputs:
            if name not in outputs:
                outputs.append(name)
    sinks = {
        name for name in graph
        if name in declared or any(item == f'{name}_sink' for item in declared)
    }
    sinks -= guards
    if not sinks:
        return []
    guard_is_output = any(name in outputs for name in guards)
    guard_is_input = any(name in inputs for name in guards)
    entries: list[str] = []
    if guard_is_output or not guard_is_input:
        entries.extend(name for name in inputs if name not in guards)
    if guard_is_input or not guard_is_output:
        entries.extend(name for name in outputs if name not in guards)
    chains: list[list[str]] = []
    seen_entries: set[str] = set()
    for entry in entries:
        if entry in seen_entries or entry not in graph:
            continue
        seen_entries.add(entry)
        chain = _shortest_avoiding(graph, entry, sinks, guards)
        if chain:
            chains.append(chain)
    chains.sort(key=lambda item: (len(item), item))
    return chains


def _ngx_module_rest(name: str) -> tuple[str, str] | None:
    parts = str(name).split('_')
    if len(parts) < 4 or parts[0] != 'ngx':
        return None
    return parts[1], '_'.join(parts[2:])


def parallel_module_chains(case_ir: dict[str, Any],
                           guard_names: list[str],
                           sink_names: list[str]) -> list[list[str]]:
    root = _source_root(case_ir)
    origin = ((case_ir.get('defect_anchors') or {}).get('root_cause_site') or {}).get('function')
    if root is None or not origin or not sink_names:
        return []
    origin_parts = _ngx_module_rest(str(origin))
    sink_parts = _ngx_module_rest(str(sink_names[0]))
    if origin_parts is None or sink_parts is None or origin_parts[0] != sink_parts[0]:
        return []
    module, entry_rest = origin_parts
    _sink_module, sink_rest = sink_parts
    if not entry_rest or entry_rest == sink_rest:
        return []
    guards = {str(name) for name in guard_names if name}
    entry_re = re.compile(rf'(?<![\w])ngx_([A-Za-z0-9]+)_{re.escape(entry_rest)}(?![\w])')
    sink_re = re.compile(rf'(?<![\w])ngx_([A-Za-z0-9]+)_{re.escape(sink_rest)}(?![\w])')
    chains: list[list[str]] = []
    seen: set[str] = set()
    token = entry_rest.split('_')[0]
    for path in sorted(root.rglob(f'*{token}*.c')):
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        stripped = _strip_c_comments(text)
        entries = {
            item.group(1): f'ngx_{item.group(1)}_{entry_rest}'
            for item in entry_re.finditer(stripped)
            if item.group(1) != module
        }
        sinks = {
            item.group(1): f'ngx_{item.group(1)}_{sink_rest}'
            for item in sink_re.finditer(stripped)
            if item.group(1) != module
        }
        for other, entry_name in entries.items():
            sink_name = sinks.get(other)
            if not sink_name or entry_name in seen or entry_name in guards:
                continue
            if not re.search(rf'(?:->|\.)\s*[A-Za-z_]\w*\s*=\s*{re.escape(sink_name)}\s*;', stripped):
                continue
            if _function_definition_kind(text, entry_name) is None:
                continue
            if _function_definition_kind(text, sink_name) is None:
                continue
            seen.add(entry_name)
            chains.append([entry_name, sink_name])
    chains.sort()
    return chains


def carrier_increment_bypasses(case_ir: dict[str, Any], guard_names: list[str]) -> list[str]:
    root = _source_root(case_ir)
    expr = str(((case_ir.get('defect_anchors') or {}).get('state_carrier') or {}).get('expr') or '')
    match = re.search(r'->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*$', expr)
    if root is None or match is None:
        return []
    pattern = re.compile(
        rf'->\s*{re.escape(match.group(1))}\s*->\s*{re.escape(match.group(2))}\s*(?:\+\+|\+=)'
    )
    guards = {str(name) for name in guard_names if name}
    found: list[str] = []
    seen: set[str] = set()
    for path in sorted(root.rglob('*.c')):
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        if not pattern.search(_strip_c_comments(text)):
            continue
        defined = _defined_functions(_expand_definition_macros(path, text))
        if any(name in guards for name, _body, _static in defined):
            continue
        for name, body, _static in defined:
            if name in guards or name in seen or not pattern.search(body):
                continue
            seen.add(name)
            found.append(name)
    found.sort()
    return found


def request_finalize_bypasses(case_ir: dict[str, Any], guard_names: list[str]) -> list[str]:
    root = _source_root(case_ir)
    expr = str(((case_ir.get('defect_anchors') or {}).get('state_carrier') or {}).get('expr') or '')
    match = re.search(r'->\s*([A-Za-z_]\w*)\s*->\s*blocked\s*$', expr)
    if root is None or match is None:
        return []
    finalize = re.compile(r'(?<![\w])[A-Za-z_]\w*_finalize_request\s*\(')
    carrier = re.compile(r'(?<![\w])blocked(?![\w])')
    writing = re.compile(r'->\s*writing\b')
    guards = {str(name) for name in guard_names if name}
    found: list[str] = []
    seen: set[str] = set()
    for path in sorted(root.rglob('*.c')):
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        stripped = _strip_c_comments(text)
        if not writing.search(stripped) or not finalize.search(stripped):
            continue
        defined = _defined_functions(_expand_definition_macros(path, text))
        if any(name in guards for name, _body, _static in defined):
            continue
        for name, body, _static in defined:
            if name in guards or name in seen:
                continue
            if carrier.search(body) or not writing.search(body) or not finalize.search(body):
                continue
            seen.add(name)
            found.append(name)
    found.sort()
    return found


def null_input_branches(case_ir: dict[str, Any],
                        guard_names: list[str],
                        sink_names: list[str]) -> list[str]:
    root = _source_root(case_ir)
    scope = case_ir.get('symbolization_scope') or {}
    inputs: list[str] = []
    for item in scope.get('symbolic_inputs') or []:
        if isinstance(item, str) and item.isidentifier():
            inputs.append(item)
        elif isinstance(item, dict) and str(item.get('name') or '').isidentifier():
            inputs.append(str(item['name']))
    if root is None or not inputs:
        return []
    wanted: list[str] = []
    for name in [*guard_names, *sink_names]:
        if name and str(name) not in wanted:
            wanted.append(str(name))
    anchors: list[Path] = []
    defect = case_ir.get('defect_anchors') or {}
    for key in ('sink_site', 'root_cause_site'):
        rel = (defect.get(key) or {}).get('file')
        if rel:
            anchors.append(root / str(rel))
    field_re = re.compile(r'->\s*([A-Za-z_]\w*)\s*==\s*NULL\b')
    input_set = set(inputs)
    found: list[str] = []
    seen: set[str] = set()
    for name in wanted:
        path: Path | None = None
        for anchor in anchors:
            if not anchor.is_file():
                continue
            try:
                text = anchor.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            if _function_definition_kind(text, name):
                path = anchor
                break
        if path is None:
            path = locate_function_source(root, name, anchors)
        if path is None or not path.is_file():
            continue
        body = _function_body_at(path, name)
        if not body:
            continue
        for field in field_re.findall(body):
            if field not in input_set:
                continue
            label = f'{name}_null_{field}_branch'
            if label in seen:
                continue
            seen.add(label)
            found.append(label)
    return found


def handler_redirect_bypasses(case_ir: dict[str, Any], guard_names: list[str]) -> list[str]:
    root = _source_root(case_ir)
    tokens = _seed_tokens(case_ir)
    if root is None or 'internal' not in tokens or 'redirect' not in tokens:
        return []
    hook = re.compile(r'(?<![\w])ap_hook_handler\s*\(\s*([A-Za-z_]\w*)')
    guards = {str(name) for name in guard_names if name}
    hooked: set[str] = set()
    for path in sorted(root.rglob('*.c')):
        try:
            text = _strip_c_comments(path.read_text(encoding='utf-8', errors='replace'))
        except OSError:
            continue
        if 'ap_hook_handler' not in text:
            continue
        hooked.update(hook.findall(text))
        if guards & hooked and hooked - guards:
            break
    found: list[str] = []
    for name in guard_names:
        if name not in hooked or not (hooked - {str(name)}):
            continue
        stem = str(name)[:-8] if str(name).endswith('_handler') else str(name)
        label = f'non_{stem}_internal_redirect_handlers'
        if label not in found:
            found.append(label)
    return found


_DIRECT_BLOCK_SWITCH = re.compile(
    r'if\s*\(\s*([A-Za-z_]\w*)\s*==\s*1\s*\)\s*\{'
    r'.*?'
    r'else\s+if\s*\(\s*\1\s*==\s*0\s*\)\s*\{'
    r'.*?'
    r'else\s*\{'
    r'.*?'
    r'\1\s*-=',
    re.S,
)


def _anchored_function_body(case_ir: dict[str, Any], name: str) -> str | None:
    root = _source_root(case_ir)
    if root is None or not name:
        return None
    defect = case_ir.get('defect_anchors') or {}
    anchors: list[Path] = []
    for key in ('sink_site', 'root_cause_site'):
        rel = (defect.get(key) or {}).get('file')
        if rel:
            anchors.append(root / str(rel))
    for guard in case_ir.get('guards') or []:
        rel = guard.get('source_file')
        if rel:
            anchors.append(root / str(rel))
    for anchor in anchors:
        if not anchor.is_file():
            continue
        try:
            text = anchor.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        if _function_definition_kind(text, name):
            return _function_body_at(anchor, name)
    path = locate_function_source(root, name, anchors)
    if path is None or not path.is_file():
        return None
    return _function_body_at(path, name)


def direct_block_switches(case_ir: dict[str, Any], guard_names: list[str]) -> list[str]:
    if _source_root(case_ir) is None:
        return []
    names: list[str] = []
    for name in guard_names:
        if name and str(name) not in names:
            names.append(str(name))
    origin = ((case_ir.get('defect_anchors') or {}).get('root_cause_site') or {}).get('function')
    if origin and str(origin) not in names:
        names.append(str(origin))
    found: list[str] = []
    for name in names:
        body = _anchored_function_body(case_ir, name)
        if not body:
            continue
        if not any('block' in item.group(1) for item in _DIRECT_BLOCK_SWITCH.finditer(body)):
            continue
        label = f'{name}_direct_block_switch'
        if label not in found:
            found.append(label)
    return found


_GLOBAL_MODULE = {
    'PS': 'session',
    'SG': 'sapi',
    'PG': 'core',
    'EG': 'executor',
    'CG': 'compiler',
}


def shutdown_other_global_bypasses(case_ir: dict[str, Any]) -> list[str]:
    root = _source_root(case_ir)
    carrier = (case_ir.get('defect_anchors') or {}).get('state_carrier') or {}
    if root is None or str(carrier.get('lifetime') or '') not in {'request', 'worker'}:
        return []
    match = re.fullmatch(r'([A-Z]{2})\(([A-Za-z_]\w*)\)', str(carrier.get('expr') or '').strip())
    if match is None:
        return []
    prefix, field = match.group(1), match.group(2)
    module = _GLOBAL_MODULE.get(prefix)
    if not module:
        return []
    path = locate_function_source(root, 'php_request_shutdown')
    if path is None or not path.is_file():
        return []
    body = _function_body_at(path, 'php_request_shutdown')
    if not body or f'{prefix}({field})' in body:
        return []
    if re.search(r'(?<![\w])(?:PG|EG|SG|CG|PS)\s*\(', body) is None:
        return []
    return [f'php_request_shutdown_non_{module}_globals']


def non_multipart_oom_bypasses(case_ir: dict[str, Any], guard_names: list[str]) -> list[str]:
    root = _source_root(case_ir)
    predicates = ((case_ir.get('symbolization_scope') or {}).get('extra_predicates') or [])
    if root is None or not any(re.search(r'\bis_mp\s*==\s*1\b', str(item)) for item in predicates):
        return []
    multipart = False
    for name in guard_names:
        path = locate_function_source(root, str(name))
        if path is None or not path.is_file():
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        if 'multipart' in text:
            multipart = True
            break
    if not multipart:
        return []
    found: list[str] = []
    for path in sorted(root.rglob('*alloc*.c')):
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        if 'Out of memory' not in text or 'zend_mm_safe_error' not in text:
            continue
        label = f'{path.stem}_non_multipart_oom_paths'
        if label not in found:
            found.append(label)
    return found


def discover_definition_files(case_ir: dict[str, Any], names: list[str]) -> list[Path]:
    root = _source_root(case_ir)
    if root is None:
        return []
    anchors: list[Path] = []
    defect = case_ir.get('defect_anchors') or {}
    for key in ('sink_site', 'root_cause_site'):
        rel = (defect.get(key) or {}).get('file')
        if rel:
            anchors.append(root / str(rel))
    for guard in case_ir.get('guards') or []:
        rel = guard.get('source_file')
        if rel:
            anchors.append(root / str(rel))
    found: list[Path] = []
    seen: set[Path] = set()
    for name in names:
        if not name:
            continue
        path = locate_function_source(root, str(name), anchors)
        if path is None:
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        found.append(resolved)
    return found


def _slice_texts(sym_scope: dict[str, Any]) -> list[str]:
    texts: list[str] = []
    for raw_path in sym_scope.get('slice_sources') or []:
        try:
            texts.append(Path(str(raw_path)).read_text(encoding='utf-8', errors='replace'))
        except OSError:
            continue
    return texts


def _direct_callers(sym_scope: dict[str, Any], current: str) -> list[str]:
    if not current:
        return []
    callers: list[str] = []
    for raw_path in sym_scope.get('slice_sources') or []:
        for name, body, static in _expanded_defined_functions(Path(str(raw_path))):
            if static or name == current or name in callers:
                continue
            if _body_calls(body, current):
                callers.append(name)
    return callers


def _same_file_callers(sym_scope: dict[str, Any], current: str, want_static: bool) -> list[str]:
    if not current:
        return []
    callers: list[str] = []
    for raw_path in sym_scope.get('slice_sources') or []:
        path = Path(str(raw_path))
        defined = _expanded_defined_functions(path)
        if not any(name == current for name, _body, _static in defined):
            continue
        for name, body, static in defined:
            if static != want_static or name == current or name in callers:
                continue
            if _body_calls(body, current):
                callers.append(name)
    return callers


def _callee_is_static(sym_scope: dict[str, Any], name: str) -> bool:
    if _signature_for_cut(sym_scope, name) is not None:
        return False
    found, _path = _static_signature_in_sources(sym_scope, name)
    return found is not None


def _nonstatic_callers(sym_scope: dict[str, Any], current: str) -> list[str]:
    if _callee_is_static(sym_scope, current):
        return _same_file_callers(sym_scope, current, False)
    return _direct_callers(sym_scope, current)


def _multi_direct(sym_scope: dict[str, Any], guard: str) -> tuple[list[str], bool]:
    direct = _nonstatic_callers(sym_scope, guard)
    if direct:
        return direct, False
    return _same_file_callers(sym_scope, guard, True), True


def _caller_body(sym_scope: dict[str, Any], name: str) -> str | None:
    for raw_path in sym_scope.get('slice_sources') or []:
        for found, body, _static in _expanded_defined_functions(Path(str(raw_path))):
            if found == name:
                return body
    return None


def _forwards_return(body: str, callee: str) -> bool:
    text = ' '.join(body.split())
    call = rf'{re.escape(callee)}\s*\([^;]*\)'
    if re.fullmatch(rf'return\s+\(?\s*{call}\s*\)?\s*;', text):
        return True
    stored = re.fullmatch(
        rf'(?:[A-Za-z_]\w*\s+|\*\s*)*([A-Za-z_]\w*)\s*=\s*{call}\s*;\s*return\s+\(?\s*([A-Za-z_]\w*)\s*\)?\s*;',
        text,
    )
    return stored is not None and stored.group(1) == stored.group(2)


_PATH_ATOM = r'[A-Za-z_]\w*(?:\s*\[[^\]]+\])*'
_PATH = rf'{_PATH_ATOM}(?:\s*(?:->|\.)\s*{_PATH_ATOM})*'
_INDEX_CAST = re.compile(r'\([A-Za-z_][\w*]*\)')


def _strip_wrapping_parens(text: str) -> str:
    current = text
    while len(current) >= 2 and current[0] == '(' and current[-1] == ')':
        depth = 0
        wraps = True
        for index, char in enumerate(current):
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth < 0 or depth == 0 and index != len(current) - 1:
                    wraps = False
                    break
        if not wraps or depth != 0:
            break
        current = current[1:-1]
    return current


def _strip_index_casts(text: str) -> str:
    previous = None
    current = text
    while current != previous:
        previous = current
        current = _INDEX_CAST.sub('', current)
    return current


def _operand_name(text: str) -> str:
    current = _unwrap_returned_operand((text or '').strip())
    changed = True
    while changed and current:
        changed = False
        unwrapped = _unwrap_returned_operand(current)
        if unwrapped != current:
            current = unwrapped
            changed = True
            continue
        wrapped = re.fullmatch(
            rf'\((.*)\)\s*((?:\s*\[[^\]]+\]|\s*(?:->|\.)\s*{_PATH_ATOM})+)',
            current,
        )
        if not wrapped:
            break
        inner = _unwrap_returned_operand(wrapped.group(1).strip())
        nxt = inner + re.sub(r'\s+', '', wrapped.group(2))
        if not inner or nxt == current:
            break
        current = nxt
        changed = True
    match = re.search(_PATH, current or '')
    if not match:
        return ''
    name = re.sub(r'\s+', '', match.group(0))

    def unwrap_index(found: re.Match[str]) -> str:
        raw = found.group(1)
        inner = _strip_wrapping_parens(raw)
        inner = _strip_index_casts(inner)
        inner = _strip_wrapping_parens(inner)
        folded = _const_index(inner) if inner else None
        if folded is not None:
            return '[' + folded + ']'
        return '[' + raw + ']'

    return re.sub(r'\[([^\]]+)\]', unwrap_index, name)


def _const_index(text: str) -> str | None:
    if not text or re.fullmatch(r'[+*/%()0-9a-fA-FxX<>!&|^~?:=-]+', text) is None:
        return None
    pos = 0

    def peek() -> str:
        return text[pos] if pos < len(text) else ''

    def take(op: str) -> bool:
        nonlocal pos
        if not text.startswith(op, pos):
            return False
        pos += len(op)
        return True

    def take_single(op: str) -> bool:
        if text.startswith(op + op, pos):
            return False
        return take(op)

    def c_div(left: int, right: int) -> int | None:
        if right == 0:
            return None
        negative = (left < 0) != (right < 0)
        value = abs(left) // abs(right)
        return -value if negative else value

    def c_mod(left: int, right: int) -> int | None:
        quot = c_div(left, right)
        if quot is None:
            return None
        return left - quot * right

    def number() -> int | None:
        nonlocal pos
        found = re.match(r'0[xX][0-9a-fA-F]+|\d+', text[pos:])
        if found is None:
            return None
        pos += len(found.group(0))
        return int(found.group(0), 0)

    def primary() -> int | None:
        nonlocal pos
        if peek() != '(':
            return number()
        pos += 1
        value = expr()
        if value is None or peek() != ')':
            return None
        pos += 1
        return value

    def unary() -> int | None:
        nonlocal pos
        if take('!'):
            value = unary()
            if value is None:
                return None
            return 0 if value else 1
        if take('~'):
            value = unary()
            if value is None:
                return None
            return ~value
        sign = 1
        while peek() in {'+', '-'}:
            if peek() == '-':
                sign = -sign
            pos += 1
        value = primary()
        if value is None:
            return None
        return sign * value

    def mul() -> int | None:
        value = unary()
        if value is None:
            return None
        while True:
            if take('*'):
                rhs = unary()
                if rhs is None:
                    return None
                value *= rhs
            elif take('/'):
                rhs = unary()
                if rhs is None:
                    return None
                quot = c_div(value, rhs)
                if quot is None:
                    return None
                value = quot
            elif take('%'):
                rhs = unary()
                if rhs is None:
                    return None
                quot = c_mod(value, rhs)
                if quot is None:
                    return None
                value = quot
            else:
                return value

    def add() -> int | None:
        nonlocal pos
        value = mul()
        if value is None:
            return None
        while peek() in {'+', '-'}:
            op = peek()
            pos += 1
            rhs = mul()
            if rhs is None:
                return None
            value = value + rhs if op == '+' else value - rhs
        return value

    def shift() -> int | None:
        value = add()
        if value is None:
            return None
        while True:
            if take('<<'):
                rhs = add()
                if rhs is None or rhs < 0 or rhs > 63:
                    return None
                value <<= rhs
            elif take('>>'):
                rhs = add()
                if rhs is None or rhs < 0 or rhs > 63:
                    return None
                value >>= rhs
            else:
                return value

    def relational() -> int | None:
        value = shift()
        if value is None:
            return None
        while True:
            if take('<='):
                rhs = shift()
                bit = value <= rhs if rhs is not None else None
            elif take('>='):
                rhs = shift()
                bit = value >= rhs if rhs is not None else None
            elif take('<'):
                rhs = shift()
                bit = value < rhs if rhs is not None else None
            elif take('>'):
                rhs = shift()
                bit = value > rhs if rhs is not None else None
            else:
                return value
            if rhs is None or bit is None:
                return None
            value = 1 if bit else 0

    def equality() -> int | None:
        value = relational()
        if value is None:
            return None
        while True:
            if take('=='):
                rhs = relational()
                bit = value == rhs if rhs is not None else None
            elif take('!='):
                rhs = relational()
                bit = value != rhs if rhs is not None else None
            else:
                return value
            if rhs is None or bit is None:
                return None
            value = 1 if bit else 0

    def bit_and() -> int | None:
        value = equality()
        if value is None:
            return None
        while take_single('&'):
            rhs = equality()
            if rhs is None:
                return None
            value &= rhs
        return value

    def bit_xor() -> int | None:
        value = bit_and()
        if value is None:
            return None
        while take('^'):
            rhs = bit_and()
            if rhs is None:
                return None
            value ^= rhs
        return value

    def bit_or() -> int | None:
        value = bit_xor()
        if value is None:
            return None
        while take_single('|'):
            rhs = bit_xor()
            if rhs is None:
                return None
            value |= rhs
        return value

    def log_and() -> int | None:
        value = bit_or()
        if value is None:
            return None
        while take('&&'):
            rhs = bit_or()
            if rhs is None:
                return None
            value = 1 if value and rhs else 0
        return value

    def log_or() -> int | None:
        value = log_and()
        if value is None:
            return None
        while take('||'):
            rhs = log_and()
            if rhs is None:
                return None
            value = 1 if value or rhs else 0
        return value

    def expr() -> int | None:
        nonlocal pos
        value = log_or()
        if value is None or not take('?'):
            return value
        then = expr()
        if then is None or not take(':'):
            return None
        otherwise = expr()
        if otherwise is None:
            return None
        return then if value else otherwise

    value = expr()
    if value is None or pos != len(text):
        return None
    return str(value)


def _canon_deref(text: str) -> str:
    previous = None
    current = text
    while current != previous:
        previous = current
        cursor = 0
        while True:
            match = re.search(r'\(\s*\*', current[cursor:])
            if not match:
                break
            open_at = cursor + match.start()
            depth = 0
            end = None
            for index in range(open_at, len(current)):
                if current[index] == '(':
                    depth += 1
                elif current[index] == ')':
                    depth -= 1
                    if depth == 0:
                        end = index
                        break
            if end is None:
                break
            inner = current[cursor + match.end():end].strip()
            compact = re.sub(r'\s+', '', inner)
            if re.fullmatch(_PATH, compact) is None and '(' not in inner:
                cursor = open_at + 1
                continue
            tail = current[end + 1:]
            stripped = tail.lstrip()
            if stripped.startswith('->'):
                current = current[:open_at] + compact + '[0]->' + stripped[2:]
                cursor = 0
                continue
            if stripped.startswith('['):
                current = current[:open_at] + compact + '[0][' + stripped[1:]
                cursor = 0
                continue
            if stripped.startswith('.'):
                current = current[:open_at] + compact + '->' + stripped[1:]
                cursor = 0
                continue
            if stripped.startswith('='):
                current = current[:open_at] + '*' + compact + stripped
                cursor = 0
                continue
            cursor = open_at + 1
    return current


def _unwrap_call_arg(arg: str) -> str:
    raw = (arg or '').strip()
    changed = True
    while changed and raw:
        changed = False
        if raw[0] != '(':
            break
        depth = 0
        for index, char in enumerate(raw):
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth == 0:
                    if index == len(raw) - 1:
                        raw = raw[1:-1].strip()
                        changed = True
                    else:
                        inner = raw[1:index].strip()
                        if re.fullmatch(
                            r'(?:(?:struct|union|enum|const|volatile)\s+)*[A-Za-z_]\w*(?:\s*\*)*',
                            inner,
                        ):
                            raw = raw[index + 1:].strip()
                            changed = True
                    break
    return raw


def _rebind_freed_path(name: str, params: list[str], args: list[str]) -> str:
    for param, arg in zip(params, args):
        raw = _unwrap_call_arg(arg)
        dest = _operand_name(raw)
        if not dest or not param:
            continue
        if name == param:
            return dest
        if name.startswith(param + '['):
            if raw.startswith('&') and name == param + '[0]':
                return dest
            if raw.startswith('&') and name.startswith(param + '[0]->'):
                return dest + '->' + name[len(param) + len('[0]->'):]
            if raw.startswith('&') and name.startswith(param + '[0].'):
                return dest + '.' + name[len(param) + len('[0].'):]
            return dest + name[len(param):]
        if name.startswith(param + '->'):
            tail = name[len(param) + 2:]
            if raw.startswith('&'):
                return dest + '.' + tail
            return dest + '->' + tail
        if name.startswith(param + '.'):
            return dest + name[len(param):]
    return name


_FIELD_REF = rf'(?:\*?\s*{_PATH_ATOM})(?:\s*(?:->|\.)\s*{_PATH_ATOM})*'


def _rhs_call(text: str, callee: str) -> tuple[str, str] | None:
    current = _unwrap_returned_operand(text.strip())
    if not current:
        return None
    arms = _split_ternary(current)
    if arms is not None:
        for arm in arms:
            if arm.strip() == current:
                continue
            found = _rhs_call(arm, callee)
            if found:
                return found
        return None
    parts = _split_call_args(current)
    if len(parts) >= 2:
        return _rhs_call(parts[-1], callee)
    call = re.fullmatch(r'([A-Za-z_]\w*)\s*\((.*)\)', current)
    if not call or call.group(1) == callee:
        return None
    return call.group(1), call.group(2)


def _value_path(text: str) -> str:
    current = _unwrap_returned_operand(text.strip())
    if not current:
        return ''
    arms = _split_ternary(current)
    if arms is not None:
        for arm in arms:
            if arm.strip() == current:
                continue
            found = _value_path(arm)
            if found:
                return found
        return ''
    parts = _split_call_args(current)
    if len(parts) >= 2:
        return _value_path(parts[-1])
    return _operand_name(current)


_CALL_KEYWORDS = frozenset({
    'if', 'while', 'for', 'switch', 'return', 'sizeof', 'typeof',
    'alignof', '_Alignof', '_Generic', 'static_assert', '_Static_assert',
})


def _balanced_calls(text: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    index = 0
    while index < len(text):
        match = re.search(r'(?<![\w])([A-Za-z_]\w*)\s*\(', text[index:])
        if not match:
            break
        open_at = index + match.end() - 1
        depth = 0
        end = None
        for pos in range(open_at, len(text)):
            if text[pos] == '(':
                depth += 1
            elif text[pos] == ')':
                depth -= 1
                if depth == 0:
                    end = pos
                    break
        if end is None:
            break
        if match.group(1) in _CALL_KEYWORDS:
            index = open_at + 1
            continue
        found.append((match.group(1), text[open_at + 1:end].strip()))
        index = end + 1
    return found


def _statement_resources(stmt: str, callee: str) -> tuple[str, str] | None:
    assign = re.fullmatch(
        rf'(?:[A-Za-z_]\w*\s+|\*\s*)*({_FIELD_REF})\s*=(?!=)\s*(.+)',
        stmt,
    )
    if assign:
        found = _rhs_call(assign.group(2), callee)
        if found:
            func, raw_arg = found
            dest = _operand_name(assign.group(1))
            arg = _operand_name(raw_arg)
            acquired = dest if dest and _frame_acquires_resource(func) else ''
            released = arg if arg and _frame_closes_resource(func) else ''
            if acquired or released:
                return acquired, released
            return None
    call = re.fullmatch(r'([A-Za-z_]\w*)\s*\((.*)\)', stmt)
    if not call or call.group(1) == callee:
        return None
    func = call.group(1)
    arg = _value_path(call.group(2))
    if not arg:
        return None
    if _frame_closes_resource(func):
        return '', arg
    if _argument_acquire(func):
        return arg, ''
    return None


def _protocol_handoff_stmt(stmt: str, callee: str) -> bool:
    from .planner import _is_protocol_handoff
    call = re.fullmatch(r'([A-Za-z_]\w*)\s*\((.*)\)', stmt)
    if call and call.group(1) != callee:
        return _is_protocol_handoff(call.group(1))
    assign = re.fullmatch(
        rf'(?:[A-Za-z_]\w*\s+|\*\s*)*({_FIELD_REF})\s*=\s*([A-Za-z_]\w*)\s*\((.*)\)',
        stmt,
    )
    return bool(assign and assign.group(2) != callee and _is_protocol_handoff(assign.group(2)))


def _alias_pairs(stmt: str) -> list[tuple[str, str]]:
    found: list[tuple[str, str]] = []
    for assigned in re.finditer(rf'(?<![\w])({_FIELD_REF})\s*=(?!=)\s*', stmt):
        dest = _operand_name(assigned.group(1))
        if not dest:
            continue
        for src in _alias_sources(_assigned_rhs(stmt, assigned.end())):
            found.append((dest, src))
    return found


def _plain_alias(stmt: str) -> tuple[str, str] | None:
    pairs = _alias_pairs(stmt)
    if not pairs:
        return None
    return pairs[0]


def _split_call_args(text: str) -> list[str]:
    args: list[str] = []
    depth = 0
    start = 0
    for index, char in enumerate(text):
        if char == '(':
            depth += 1
        elif char == ')':
            depth = max(0, depth - 1)
        elif char == ',' and depth == 0:
            args.append(text[start:index].strip())
            start = index + 1
    tail = text[start:].strip()
    if tail:
        args.append(tail)
    return args


def _rename_root(names: dict[str, int], old: str, new: str) -> None:
    if not old or not new or old == new:
        return
    for key in list(names):
        if key == old or key.startswith(old + '->') or key.startswith(old + '.') or key.startswith(old + '['):
            names[new + key[len(old):]] = names.pop(key)


def _bare_local_name(stmt: str) -> str:
    if '(' in stmt:
        return ''
    match = re.fullmatch(r'([A-Za-z_]\w*)(?:\s+\*?\s*[A-Za-z_]\w*)*\s+\*?\s*([A-Za-z_]\w*)\s*', stmt)
    if not match or match.group(1) in {'return', 'if', 'else', 'for', 'while', 'switch', 'goto', 'case', 'do', 'break', 'continue'}:
        return ''
    return match.group(2)


def _declares_local(stmt: str, name: str) -> bool:
    if not name or '->' in name or '.' in name or name == '@return':
        return False
    return re.fullmatch(
        rf'(?:[A-Za-z_]\w*\s+)+(?:\*\s*)*{re.escape(name)}\s*=\s*.*',
        stmt,
    ) is not None


def _unwrap_returned_operand(text: str) -> str:
    current = text.strip()
    changed = True
    while changed and current:
        changed = False
        cast = re.match(
            r'\(\s*(?:(?:struct|union|enum|const|volatile|signed|unsigned)\s+)*[A-Za-z_]\w*(?:\s*\*)*\s*\)\s*',
            current,
        )
        if cast:
            current = current[cast.end():].strip()
            changed = True
            continue
        if len(current) < 2 or current[0] != '(' or current[-1] != ')':
            break
        depth = 0
        wraps = True
        for index, char in enumerate(current):
            if char == '(':
                depth += 1
            elif char == ')':
                depth -= 1
                if depth < 0 or depth == 0 and index != len(current) - 1:
                    wraps = False
                    break
        if not wraps or depth != 0:
            break
        current = current[1:-1].strip()
        changed = True
    return current


def _split_ternary(text: str) -> tuple[str, str] | None:
    paren = 0
    questions = 0
    question_at = -1
    for index, char in enumerate(text):
        if char == '(':
            paren += 1
        elif char == ')':
            paren = max(0, paren - 1)
        elif paren:
            continue
        elif char == '?':
            if questions == 0:
                question_at = index
            questions += 1
        elif char == ':' and questions:
            questions -= 1
            if questions == 0:
                return text[question_at + 1:index], text[index + 1:]
    return None


def _assigned_rhs(text: str, start: int) -> str:
    depth = 0
    for index in range(start, len(text)):
        char = text[index]
        if char == '(':
            depth += 1
        elif char == ')':
            if depth == 0:
                return text[start:index]
            depth -= 1
        elif depth == 0 and char in ',;':
            return text[start:index]
    return text[start:]


def _alias_sources(text: str) -> list[str]:
    current = _unwrap_returned_operand(text.strip())
    if not current:
        return []
    name = _operand_name(current)
    if name and re.sub(r'\s+', '', current) == name:
        return [name]
    arms = _split_ternary(current)
    if arms is not None:
        return _alias_sources(arms[0]) + _alias_sources(arms[1])
    parts = _split_call_args(current)
    if len(parts) >= 2:
        return _alias_sources(parts[-1])
    return []


def _value_is_callee(text: str, callee: str) -> bool:
    current = _unwrap_returned_operand(text)
    if re.fullmatch(rf'{re.escape(callee)}\s*\(.*\)', current):
        return True
    arms = _split_ternary(current)
    if arms is not None:
        return _value_is_callee(arms[0], callee) or _value_is_callee(arms[1], callee)
    parts = _split_call_args(current)
    if len(parts) >= 2:
        return _value_is_callee(parts[-1], callee)
    return False


def _return_operand(stmt: str) -> str:
    match = re.search(r'(?<![\w])return\b\s*(.*)', stmt)
    if not match:
        return ''
    return match.group(1).strip()


def _returns_callee(stmt: str, callee: str) -> bool:
    operand = _return_operand(stmt)
    if not operand:
        return False
    return _value_is_callee(operand, callee)


def _closes_returned_call(stmt: str, callee: str) -> bool:
    match = re.fullmatch(r'([A-Za-z_]\w*)\s*\((.*)\)', stmt)
    if not match or not _frame_closes_resource(match.group(1)):
        return False
    operand = _unwrap_returned_operand(match.group(2))
    return re.fullmatch(rf'{re.escape(callee)}\s*\(.*\)', operand) is not None


def _returned_path(argument: str, callee: str) -> str:
    text = _unwrap_returned_operand(argument.strip())
    if not text:
        return ''
    arms = _split_ternary(text)
    if arms is not None:
        for arm in arms:
            found = _returned_path(arm, callee)
            if found:
                return found
        return ''
    parts = _split_call_args(text)
    if len(parts) >= 2:
        return _returned_path(parts[-1], callee)
    wrapped = re.fullmatch(
        rf'\((.*)\)\s*((?:\s*\[[^\]]+\]|\s*(?:->|\.)\s*{_PATH_ATOM})+)',
        text,
    )
    if wrapped:
        base = _returned_path(wrapped.group(1), callee)
        if base:
            return base + re.sub(r'\s+', '', wrapped.group(2))
    match = re.search(rf'(?<![\w]){re.escape(callee)}\s*\(', text)
    if not match:
        return ''
    depth = 0
    end = None
    for index in range(match.end() - 1, len(text)):
        char = text[index]
        if char == '(':
            depth += 1
        elif char == ')':
            depth -= 1
            if depth == 0:
                end = index + 1
                break
    if end is None:
        return ''
    current = (text[:match.start()] + '@return' + text[end:]).strip()
    changed = True
    while changed and current:
        changed = False
        unwrapped = _unwrap_returned_operand(current)
        if unwrapped != current:
            current = unwrapped
            changed = True
            continue
        wrapped = re.fullmatch(
            rf'\((.*)\)\s*((?:\s*\[[^\]]+\]|\s*(?:->|\.)\s*{_PATH_ATOM})+)',
            current,
        )
        if not wrapped:
            break
        inner = _unwrap_returned_operand(wrapped.group(1).strip())
        if not inner.startswith('@return'):
            break
        current = inner + re.sub(r'\s+', '', wrapped.group(2))
        changed = True
    current = re.sub(r'\s+', '', current)
    if re.fullmatch(rf'@return(?:\[[^\]]+\])*(?:(?:->|\.){_PATH_ATOM})*', current) is None:
        return ''
    folded = _operand_name('vg_return' + current[len('@return'):])
    if folded == 'vg_return' or folded.startswith('vg_return->') or folded.startswith('vg_return.') or folded.startswith('vg_return['):
        return '@return' + folded[len('vg_return'):]
    return current


def _retarget_outputs(names: dict[str, int], params: list[str], args: list[str]) -> None:
    for param, arg in zip(params, args):
        if not param or param not in names:
            continue
        dest = _operand_name(_unwrap_call_arg(arg))
        if not dest:
            continue
        names[dest] = names[param]
        if dest != param:
            del names[param]


def _lift_step_body(body: str | None,
                    callee: str,
                    live: dict[str, int] | None = None,
                    params: list[str] | None = None,
                    owner: str = '',
                    owner_params: list[str] | None = None,
                    summaries: dict[str, tuple[set[str], set[str], list[tuple[str, str]]]] | None = None,
                    lookup=None,
                    stacking: set[str] | None = None) -> str:
    if live is None:
        live = {}
    if summaries is None:
        summaries = {}
    if stacking is None:
        stacking = set()
    owner_params = owner_params or []

    def ensure_summary(func: str) -> None:
        if not func or func in summaries or func == callee or func in stacking or lookup is None or len(stacking) > 8:
            return
        found = lookup(func)
        if not found or not found[0]:
            summaries[func] = (set(), set(), [])
            return
        stacking.add(func)
        _lift_step_body(found[0], '', {}, found[1], func, found[1], summaries, lookup, stacking)
        stacking.discard(func)

    def argument_root(arg: str) -> str:
        if callee:
            rooted = _returned_path(arg, callee)
            if rooted:
                return rooted
        fresh = fresh_argument(arg)
        if fresh:
            return fresh
        text = _unwrap_returned_operand(arg.strip())
        compact = re.sub(r'\s+', '', text)
        if compact in aliases:
            return argument_root(aliases[compact])
        arms = _split_ternary(text)
        if arms is not None:
            for arm in arms:
                if arm.strip() == text:
                    continue
                found = argument_root(arm)
                if found:
                    return found
            return ''
        parts = _split_call_args(text)
        if len(parts) >= 2:
            return argument_root(parts[-1])
        return _operand_name(_unwrap_call_arg(text))

    aliases: dict[str, str] = {}

    def object_arg(arg: str) -> str:
        text = _unwrap_returned_operand(arg.strip())
        if not text:
            return arg
        if text in aliases:
            return object_arg(aliases[text])
        arms = _split_ternary(text)
        if arms is not None:
            for arm in arms:
                if arm.strip() == text:
                    continue
                found = object_arg(arm)
                if found and found != arm.strip():
                    return found
            return arg
        parts = _split_call_args(text)
        if len(parts) >= 2 and re.fullmatch(r'([A-Za-z_]\w*)\s*\((.*)\)', text) is None:
            return object_arg(parts[-1])
        call = re.fullmatch(r'([A-Za-z_]\w*)\s*\((.*)\)', text)
        if not call or call.group(1) == callee or lookup is None:
            return arg
        func = call.group(1)
        ensure_summary(func)
        moved = summaries.get(func, (set(), set(), []))[2]
        found = lookup(func)
        params_here = list(found[1] or []) if found else []
        inner_args = _split_call_args(call.group(2))
        for src, dest in moved:
            if dest != '@return' or '->' in src or '.' in src or '[' in src:
                continue
            for param, inner in zip(params_here, inner_args):
                if param == src:
                    return object_arg(inner)
        return arg

    def callee_args(text: str) -> str | None:
        if not callee:
            return None
        for func, raw_args in _balanced_calls(text):
            if func == callee:
                return raw_args
            found = callee_args(raw_args)
            if found is not None:
                return found
        return None

    def returned_owner(text: str, seen: set[str] | None = None) -> str:
        current = _unwrap_returned_operand(text.strip())
        if not current:
            return ''
        arms = _split_ternary(current)
        if arms is not None:
            for arm in arms:
                if arm.strip() == current:
                    continue
                found = returned_owner(arm, seen)
                if found:
                    return found
            return ''
        parts = _split_call_args(current)
        if len(parts) >= 2 and re.fullmatch(r'([A-Za-z_]\w*)\s*\((.*)\)', current) is None:
            return returned_owner(parts[-1], seen)
        name = _operand_name(current)
        compact = re.sub(r'\s+', '', current)
        if name and compact == name and name in aliases:
            seen = seen or set()
            if name in seen:
                return ''
            seen.add(name)
            return returned_owner(aliases[name], seen)
        if name and name in owner_params and '->' not in name and '.' not in name and '[' not in name and compact == name:
            return name
        call = re.fullmatch(r'([A-Za-z_]\w*)\s*\((.*)\)', current)
        if not call or call.group(1) == callee or lookup is None:
            return ''
        func = call.group(1)
        ensure_summary(func)
        moved = summaries.get(func, (set(), set(), []))[2]
        found_fn = lookup(func)
        params_here = list(found_fn[1] or []) if found_fn else []
        inner_args = _split_call_args(call.group(2))
        for src, dest in moved:
            if dest != '@return' or '->' in src or '.' in src or '[' in src:
                continue
            for param, inner in zip(params_here, inner_args):
                if param == src:
                    return returned_owner(inner, seen)
        return ''

    def bind_freed(freed: str, helper_params: list[str], args: list[str]) -> str:
        for param, arg in zip(helper_params, args):
            root = argument_root(arg)
            if not param or not root:
                continue
            if freed == param or freed.startswith(param + '->') or freed.startswith(param + '.') or freed.startswith(param + '['):
                if freed == param + '[0]' and arg.strip().startswith('&'):
                    return root
                return root + freed[len(param):]
        return _rebind_freed_path(freed, helper_params, args)
    if body is None:
        return 'hold' if live else 'forward'
    names = dict(live)
    born: set[int] = set()
    locals_here: set[str] = set()
    params_freed: set[str] = set()
    names_freed: set[str] = set()
    moves: list[tuple[str, str]] = []
    skipped_stmts: set[str] = set()
    next_id = max(names.values(), default=0)
    released_live = False

    def plant(dest_name: str) -> None:
        nonlocal next_id
        if not dest_name:
            return
        next_id += 1
        names[dest_name] = next_id
        born.add(next_id)
        root = dest_name.split('->', 1)[0].split('.', 1)[0].split('[', 1)[0]
        if root in owner_params and ('@born', dest_name) not in moves:
            moves.append(('@born', dest_name))

    fresh_cache: dict[str, str] = {}

    def fresh_argument(arg: str) -> str:
        nonlocal next_id
        text = _unwrap_returned_operand(arg.strip())
        if text in fresh_cache:
            return fresh_cache[text]
        arms = _split_ternary(text)
        if arms is not None:
            for arm in arms:
                found = fresh_argument(arm)
                if found:
                    fresh_cache[text] = found
                    return found
            return ''
        parts = _split_call_args(text)
        if len(parts) >= 2:
            found = fresh_argument(parts[-1])
            if found:
                fresh_cache[text] = found
            return found
        match = re.fullmatch(r'([A-Za-z_]\w*)\s*\((.*)\)', text)
        if not match or match.group(1) == callee:
            return ''
        func = match.group(1)
        owned = _frame_acquires_resource(func) or _argument_acquire(func)
        if not owned:
            ensure_summary(func)
            moved = summaries.get(func, (set(), set(), []))[2]
            owned = ('@born', '@return') in moved
        if not owned:
            return ''
        next_id += 1
        key = f'@call{next_id}'
        names[key] = next_id
        born.add(next_id)
        fresh_cache[text] = key
        return key

    abandoned = False

    def remember(name: str) -> None:
        if not name or name.startswith('@') or '->' in name or '.' in name:
            if name and ('->' in name or '.' in name) and name not in owner_params:
                ident = names.get(name)
                if ident is None or ident not in born:
                    names_freed.add(name)
            return
        if name in owner_params:
            params_freed.add(name)
            return
        ident = names.get(name)
        if ident is not None and ident in born:
            return
        names_freed.add(name)

    def note_unseen(name: str) -> None:
        root = name.split('->', 1)[0].split('.', 1)[0].split('[', 1)[0]
        if root in owner_params:
            remember(name)

    def alias_name(name: str, seen: set[str] | None = None) -> str:
        seen = seen or set()
        best = ''
        for key in aliases:
            if name == key or name.startswith(key + '->') or name.startswith(key + '.') or name.startswith(key + '['):
                if len(key) > len(best):
                    best = key
        if not best or best in seen:
            return name
        seen.add(best)
        return alias_name(aliases[best] + name[len(best):], seen)

    def release_name(name: str) -> None:
        nonlocal released_live
        if name and name not in names:
            mapped = alias_name(name)
            if mapped in names:
                name = mapped
        if not name or name not in names:
            remember(name)
            return
        ident = names[name]
        if ident not in born:
            released_live = True
        remember(name)
        for key, value in list(names.items()):
            if value == ident:
                del names[key]
        born.discard(ident)
    for raw in ' '.join(body.split()).split(';'):
        stmt = _canon_deref(raw.strip())
        fresh_cache.clear()
        if not stmt:
            continue
        bare = _bare_local_name(stmt)
        if bare:
            locals_here.add(bare)
        called_args = callee_args(stmt)
        called = called_args is not None
        if called:
            freed_params, freed_names, moved = summaries.get(callee, (set(), set(), []))
            call_args = [object_arg(part) for part in _split_call_args(called_args)]
            for key in list(names):
                if '->' not in key and '.' not in key:
                    continue
                rebound = _rebind_freed_path(key, params or [], call_args)
                if rebound and rebound != key:
                    names[rebound] = names.pop(key)
            for param, arg in zip(params or [], call_args):
                if param in freed_params:
                    release_name(_operand_name(_unwrap_call_arg(arg)))
            for freed in freed_names:
                release_name(_rebind_freed_path(freed, params or [], call_args))
            for src, dest in moved:
                src_name = _rebind_freed_path(src, params or [], call_args)
                dest_name = _rebind_freed_path(dest, params or [], call_args)
                if not src_name or not dest_name or dest_name == src_name:
                    continue
                if '->' not in dest_name and '.' not in dest_name:
                    continue
                if src_name == '@born':
                    continue
                if src_name in names:
                    names[dest_name] = names[src_name]
                if src_name in names or src_name in owner_params:
                    moves.append((src_name, dest_name))
        if called and params:
            _retarget_outputs(names, params, call_args)
        helper_hit = False
        helper_noted = False
        for func, raw_args in _balanced_calls(stmt):
            if func == callee or _frame_acquires_resource(func) or _argument_acquire(func):
                continue
            if _frame_closes_resource(func):
                ensure_summary(func)
                freed_params, freed_names, moved = summaries.get(func, (set(), set(), []))
                if not freed_params and not freed_names and not moved:
                    continue
            else:
                ensure_summary(func)
            helper_params = []
            if lookup is not None:
                found = lookup(func)
                if found:
                    helper_params = list(found[1] or [])
            freed_params, freed_names, moved = summaries.get(func, (set(), set(), []))
            call_args = _split_call_args(raw_args)
            for param, arg in zip(helper_params, call_args):
                if param not in freed_params:
                    continue
                root = argument_root(arg)
                if root in names:
                    release_name(root)
                    helper_hit = True
                else:
                    note_unseen(root)
                    helper_noted = True
            for freed in freed_names:
                rebound = bind_freed(freed, helper_params, call_args)
                if rebound in names:
                    release_name(rebound)
                    helper_hit = True
                else:
                    note_unseen(rebound)
                    helper_noted = True
            for src, dest in moved:
                src_name = bind_freed(src, helper_params, call_args)
                dest_name = bind_freed(dest, helper_params, call_args)
                if src_name == '@born' and dest_name == '@return':
                    for assigned in re.finditer(rf'(?<![\w])({_FIELD_REF})\s*=(?!=)\s*', stmt):
                        if not _value_is_callee(_assigned_rhs(stmt, assigned.end()), func):
                            continue
                        planted = _operand_name(assigned.group(1))
                        if not planted:
                            continue
                        plant(planted)
                        helper_noted = True
                    if _returns_callee(stmt, func):
                        plant('@return')
                        helper_noted = True
                    continue
                if not src_name or not dest_name or dest_name == src_name:
                    continue
                if '->' not in dest_name and '.' not in dest_name and '[' not in dest_name and dest_name not in owner_params:
                    continue
                if src_name == '@born':
                    plant(dest_name)
                    helper_noted = True
                    continue
                if src_name in names:
                    names[dest_name] = names[src_name]
                plain_dest = '->' not in dest and '.' not in dest and '[' not in dest
                owner = src_name if plain_dest and src_name in owner_params else ''
                if plain_dest and not owner:
                    mapped = alias_name(src_name)
                    root = mapped.split('->', 1)[0].split('.', 1)[0].split('[', 1)[0]
                    if mapped == root and root in owner_params:
                        owner = root
                if owner and dest_name != owner:
                    aliases[dest_name] = owner
                if src_name in names or src_name in owner_params:
                    moves.append((src_name, dest_name))
                    helper_noted = True
        if helper_noted and not any(
            _value_is_callee(_assigned_rhs(stmt, assigned.end()), other.group(1))
            for other in re.finditer(r'(?<![\w])([A-Za-z_]\w*)\s*\(', stmt)
            for assigned in re.finditer(rf'(?<![\w])({_FIELD_REF})\s*=(?!=)\s*', stmt)
        ):
            skipped_stmts.add(stmt)
        if helper_hit:
            continue
        if called and any(key == '@return' or key.startswith('@return->') or key.startswith('@return.') or key.startswith('@return[') for key in names):
            for assigned in re.finditer(
                rf'(?<![\w])({_FIELD_REF})\s*=(?!=)\s*',
                stmt,
            ):
                if not _value_is_callee(_assigned_rhs(stmt, assigned.end()), callee):
                    continue
                dest = _operand_name(assigned.group(1))
                if not dest:
                    continue
                _rename_root(names, '@return', dest)
                names.pop('@return', None)
                if _declares_local(stmt, dest):
                    locals_here.add(dest)
                break
        if '@return' in names and _closes_returned_call(stmt, callee):
            ident = names['@return']
            if ident not in born:
                released_live = True
            for key, value in list(names.items()):
                if value == ident:
                    del names[key]
            born.discard(ident)
            continue
        if called and '@return' in names and not _returns_callee(stmt, callee):
            ident = names['@return']
            for key, value in list(names.items()):
                if value == ident:
                    del names[key]
            abandoned = True
        closed = re.fullmatch(r'([A-Za-z_]\w*)\s*\((.*)\)', stmt)
        if closed and closed.group(1) != callee and _frame_closes_resource(closed.group(1)):
            rooted = _returned_path(closed.group(2), callee)
            if rooted and rooted in names:
                release_name(rooted)
                continue
        effect = _statement_resources(stmt, callee)
        if effect is not None:
            if effect[0]:
                next_id += 1
                names[effect[0]] = next_id
                born.add(next_id)
                if _declares_local(stmt, effect[0]):
                    locals_here.add(effect[0])
            if effect[1]:
                if _protocol_handoff_stmt(stmt, callee):
                    for key in list(names):
                        if names[key] not in born:
                            release_name(key)
                    released_live = True
                else:
                    release_name(effect[1])
                continue
        if effect is None:
            for assigned in re.finditer(rf'(?<![\w])({_FIELD_REF})\s*=(?!=)\s*', stmt):
                found = _rhs_call(_assigned_rhs(stmt, assigned.end()), callee)
                if not found:
                    continue
                func, _raw = found
                if not (_frame_acquires_resource(func) or _argument_acquire(func)):
                    continue
                dest = _operand_name(assigned.group(1))
                if not dest:
                    continue
                next_id += 1
                names[dest] = next_id
                born.add(next_id)
                if _declares_local(stmt, dest):
                    locals_here.add(dest)
            released_here = False
            for func, raw in _balanced_calls(stmt):
                if func == callee or not _frame_closes_resource(func):
                    continue
                target = _value_path(raw)
                if callee and (not target or target not in names):
                    rooted = _returned_path(raw, callee)
                    if rooted:
                        target = rooted
                if target and target not in names:
                    mapped = alias_name(target)
                    if mapped in names:
                        target = mapped
                if target and target in names:
                    release_name(target)
                    released_here = True
            if released_here:
                continue
        for dest, src in _alias_pairs(stmt):
            if (src in names or src in (params or []) or src in owner_params) and ('->' in dest or '.' in dest or dest in owner_params):
                moves.append((src, dest))
            if src in names:
                names[dest] = names[src]
        for assigned in re.finditer(rf'(?<![\w])({_FIELD_REF})\s*=(?!=)\s*', stmt):
            dest = _operand_name(assigned.group(1))
            passed = returned_owner(_assigned_rhs(stmt, assigned.end()))
            if dest and passed and dest != passed:
                aliases[dest] = passed
        returned_text = _return_operand(stmt)
        if returned_text:
            for src in _alias_sources(returned_text):
                if not src or src == '@return':
                    continue
                ident = names.get(src)
                _rename_root(names, src, '@return')
                if ident is not None:
                    for key, value in list(names.items()):
                        if value == ident and key != '@return' and '->' not in key and '.' not in key:
                            del names[key]
                if '->' not in src and '.' not in src and '[' not in src and src in owner_params and (src, '@return') not in moves:
                    moves.append((src, '@return'))
            passed = returned_owner(returned_text)
            if passed and (passed, '@return') not in moves:
                moves.append((passed, '@return'))
            found = _rhs_call(returned_text, callee)
            if found and '@return' not in names and (_frame_acquires_resource(found[0]) or _argument_acquire(found[0])):
                next_id += 1
                names['@return'] = next_id
                born.add(next_id)
    for key in list(names):
        root = key.split('->', 1)[0].split('.', 1)[0]
        if key in locals_here or root in locals_here:
            del names[key]
    for key, ident in list(names.items()):
        root = key.split('->', 1)[0].split('.', 1)[0].split('[', 1)[0]
        if root in owner_params and ident in born and (key == root or '->' in key or '.' in key or '[' in key):
            if ('@born', key) not in moves:
                moves.append(('@born', key))
    returned_id = names.get('@return')
    if returned_id is not None and returned_id in born and ('@born', '@return') not in moves:
        moves.append(('@born', '@return'))
    if owner:
        summaries[owner] = (set(params_freed), set(names_freed), list(moves))
    live.clear()
    live.update(names)
    if released_live and not live:
        return 'close'
    kept: list[str] = []
    for raw in ' '.join(body.split()).split(';'):
        stmt = _canon_deref(raw.strip())
        if not stmt or stmt in skipped_stmts or _statement_resources(stmt, callee) is not None or _plain_alias(stmt) is not None or _bare_local_name(stmt):
            continue
        kept.append(stmt)
    if live:
        return 'hold'
    if abandoned:
        return 'abandon'
    if _forwards_return('; '.join(kept) + (';' if kept else ''), callee):
        return 'forward'
    return 'stop'


def _parameter_names(sym_scope: dict[str, Any] | None, function: str, source: str = '') -> list[str]:
    signature = None
    if sym_scope is not None:
        signature = _signature_for_cut(sym_scope, function, include_static=True)
    if signature is None and source:
        signature = parse_c_function_signature(source, function, include_static=True)
    if not signature:
        return []
    return [str(item.get('name') or '') for item in signature.get('parameters') or [] if item.get('name')]


def _lift_step(sym_scope: dict[str, Any],
               caller: str,
               callee: str,
               live: dict[str, int] | None = None,
               summaries: dict[str, tuple[set[str], set[str]]] | None = None) -> str:
    def lookup(name: str) -> tuple[str | None, list[str]]:
        return _caller_body(sym_scope, name), _parameter_names(sym_scope, name)

    return _lift_step_body(
        _caller_body(sym_scope, caller),
        callee,
        live,
        _parameter_names(sym_scope, callee),
        caller,
        _parameter_names(sym_scope, caller),
        summaries,
        lookup,
    )


def _frame_closes_resource(name: str) -> bool:
    from .planner import _closes_owned_object
    if _closes_owned_object(name):
        return True
    base = name.split(':')[-1].lower()
    return base in {'fclose', 'pclose', 'efree', '_efree'} or base.endswith('_close')


def _argument_acquire(name: str) -> bool:
    from .planner import _is_acquire_callee
    return _is_acquire_callee(name)


def _frame_acquires_resource(name: str) -> bool:
    from .planner import _is_acquire_callee, _is_owning_allocator
    if _is_acquire_callee(name) or _is_owning_allocator(name):
        return True
    base = name.split(':')[-1].lower()
    if base in {'fopen', 'fdopen', 'open', 'popen'}:
        return True
    return 'create_pool' in base or 'pool_create' in base or base.endswith('_open_file') or base.endswith('_file_open')


def _note_lift(kind: str, held: bool, hops: int, extra: int, limit: int) -> tuple[str, bool, int, int]:
    if kind in {'close', 'abandon'} or (kind == 'stop' and not held):
        return 'stop', held, hops, extra
    if kind == 'hold':
        held = True
    if held:
        extra += 1
        if extra > 8:
            return 'stop', held, hops, extra
        return 'continue', held, hops, extra
    hops += 1
    if hops >= limit:
        return 'budget', held, hops, extra
    return 'continue', held, hops, extra


def lift_unique_caller(sym_scope: dict[str, Any], start: str, limit: int = 4) -> str | None:
    if not _slice_texts(sym_scope) or not start:
        return None
    current = start
    lifted: str | None = None
    held = False
    hops = 0
    extra = 0
    live: dict[str, int] = {}
    summaries: dict[str, tuple[set[str], set[str]]] = {}
    while True:
        callers = _nonstatic_callers(sym_scope, current)
        nxt: str | None = None
        if len(callers) == 1 and _signature_for_cut(sym_scope, callers[0]) is not None:
            nxt = callers[0]
        elif callers:
            break
        else:
            static_callers = _same_file_callers(sym_scope, current, True)
            if len(static_callers) != 1:
                break
            signature = _signature_for_cut(sym_scope, static_callers[0], include_static=True)
            if signature is None or signature.get('linkage') != 'static':
                break
            nxt = static_callers[0]
        lifted = nxt
        kind = _lift_step(sym_scope, nxt, current, live, summaries)
        action, held, hops, extra = _note_lift(kind, held, hops, extra, limit)
        current = nxt
        if action != 'continue':
            return lifted
    return lifted


def _trace_names(case_ir: dict[str, Any]) -> set[str]:
    names: set[str] = set()
    for trace in case_ir.get('dynamic_traces') or []:
        if not isinstance(trace, dict):
            continue
        for stack in trace.get('call_stacks') or []:
            for item in stack or []:
                names.add(str(item))
        for edge in trace.get('call_edges') or []:
            for item in edge or []:
                names.add(str(item))
    return names


def _entry_parses(sym_scope: dict[str, Any], name: str, include_static: bool) -> bool:
    if _signature_for_cut(sym_scope, name) is not None:
        return True
    if not include_static:
        return False
    signature = _signature_for_cut(sym_scope, name, include_static=True)
    return signature is not None and signature.get('linkage') == 'static'


def _caller_step_ok(sym_scope: dict[str, Any], name: str, static_group: bool) -> bool:
    signature = _signature_for_cut(sym_scope, name, include_static=static_group)
    if signature is None:
        return False
    if static_group:
        return signature.get('linkage') == 'static'
    return signature.get('linkage') != 'static'


def _expand_caller_group(sym_scope: dict[str, Any],
                         names: list[str],
                         static_group: bool,
                         case_ir: dict[str, Any] | None,
                         lift_limit: int,
                         blocked: str) -> list[str] | None:
    activated = _trace_names(case_ir or {})
    ordered = [name for name in names if name in activated]
    ordered.extend(name for name in names if name not in activated)
    entries: list[str] = []
    for name in ordered:
        if not _caller_step_ok(sym_scope, name, static_group):
            return None
        lifted = lift_unique_caller(sym_scope, name, limit=max(lift_limit, 0)) if lift_limit else None
        if lifted and lifted != blocked and _entry_parses(sym_scope, lifted, True):
            entry = lifted
        else:
            entry = name
        if entry not in entries:
            entries.append(entry)
    if not entries:
        return None
    return entries


def multi_caller_entries(sym_scope: dict[str, Any],
                         guard: str,
                         case_ir: dict[str, Any] | None = None,
                         limit: int = 4) -> list[str] | None:
    direct, static_group = _multi_direct(sym_scope, guard)
    if len(direct) < 2:
        return None
    return _expand_caller_group(
        sym_scope, direct, static_group, case_ir, max(limit - 1, 0), guard,
    )


def _name_address_taken(text: str, name: str) -> bool:
    pattern = re.compile(rf'(?<![\w]){re.escape(name)}(?![\w])')
    for match in pattern.finditer(text):
        cursor = match.end()
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor < len(text) and text[cursor] == '(':
            continue
        return True
    return False


def _call_arity(body: str, call_at: int) -> int:
    paren = body.find('(', call_at)
    if paren < 0:
        return -1
    close = _proto_match(body, paren, '(', ')')
    if close < 0:
        return -1
    inner = body[paren + 1:close].strip()
    if not inner or inner == 'void':
        return 0
    depth = 0
    count = 1
    for char in inner:
        if char in '([{':
            depth += 1
        elif char in ')]}':
            depth = max(depth - 1, 0)
        elif char == ',' and depth == 0:
            count += 1
    return count


def _indirect_sites(body: str) -> list[dict[str, Any]]:
    sites: list[dict[str, Any]] = []
    for match in re.finditer(r'(?<![\w])([A-Za-z_]\w*)\s*=\s*\*', body):
        local = match.group(1)
        call = re.search(rf'(?<![\w]){re.escape(local)}\s*\(', body[match.end():])
        if call is None:
            continue
        call_at = match.end() + call.start()
        line_start = body.rfind('\n', 0, call_at) + 1
        prefix = body[line_start:call_at].strip()
        semi = body.find(';', match.end())
        expr = body[match.end():semi if semi >= 0 else call_at]
        idents = re.findall(r'[A-Za-z_]\w*', expr)
        field = idents[-1] if idents else ''
        rhs = ''
        rhs_at = match.start()
        if field:
            prior = list(re.finditer(
                rf'(?<![\w]){re.escape(field)}\s*=\s*([^;]+)',
                body[:match.start()],
            ))
            if prior:
                rhs = ' '.join(prior[-1].group(1).split())
                rhs_at = prior[-1].start()
        sites.append({
            'rhs': rhs,
            'rhs_at': rhs_at,
            'return_used': bool(prefix),
            'arity': _call_arity(body, call_at),
        })
    return sites


def _defining_sources(sym_scope: dict[str, Any], names: set[str]) -> list[tuple[str, list[tuple[str, str, bool]]]]:
    rows: list[tuple[str, list[tuple[str, str, bool]]]] = []
    for raw_path in sym_scope.get('slice_sources') or []:
        try:
            text = Path(str(raw_path)).read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        defined = _defined_functions(text)
        if any(name in names for name, _body, _static in defined):
            rows.append((text, defined))
    return rows


def _called_by_name(text: str, name: str) -> bool:
    pattern = re.compile(rf'(?<![\w]){re.escape(name)}\s*\(')
    for match in pattern.finditer(text):
        close = _proto_match(text, match.end() - 1, '(', ')')
        if close < 0:
            continue
        cursor = close + 1
        while cursor < len(text) and text[cursor].isspace():
            cursor += 1
        if cursor < len(text) and text[cursor] == '{':
            continue
        return True
    return False


def _is_indirect_opcode(text: str, name: str, body: str) -> bool:
    if _name_address_taken(text, name):
        return True
    if _called_by_name(text, name):
        return False
    return bool(re.search(r'(?:\.|->)\s*ip\b', body))


def _indirect_dispatchers(sym_scope: dict[str, Any], names: list[str]) -> list[str]:
    if len(names) < 2:
        return []
    defining = _defining_sources(sym_scope, set(names))
    if not defining:
        return []
    blob = '\n'.join(_strip_c_comments(text) for text, _defined in defining)
    bodies = {
        name: body
        for _text, defined in defining
        for name, body, _static in defined
    }
    if not all(_is_indirect_opcode(blob, name, bodies.get(name, '')) for name in names):
        return []
    found: list[str] = []
    excluded = set(names)
    for _text, defined in defining:
        for name, body, _static in defined:
            if name in excluded or name in found or _name_address_taken(blob, name):
                continue
            signature = _signature_for_cut(sym_scope, name, include_static=True)
            if signature is None:
                continue
            params = {str(item['name']) for item in signature['parameters']}
            if any(
                _stream_slot(
                    _fed_from_local(
                        body,
                        str(site.get('rhs') or ''),
                        params,
                        int(site.get('rhs_at') or 0),
                    ),
                    params,
                )
                for site in _indirect_sites(body)
            ):
                found.append(name)
    return found


def _fed_from_local(body: str, rhs: str, params: set[str], before: int) -> str:
    text = ' '.join(str(rhs).split())
    if not re.fullmatch(r'[A-Za-z_]\w*', text) or text in params:
        return rhs
    assigns = list(re.finditer(
        rf'(?<![\w]){re.escape(text)}\s*=\s*([^;]+);',
        body[:max(before, 0)],
    ))
    if len(assigns) != 1:
        return rhs
    origin = ' '.join(assigns[0].group(1).split())
    if _stream_slot(origin, params) is None:
        return rhs
    return origin


def _stream_slot(rhs: str, params: set[str]) -> tuple[str, str | None] | None:
    text = ' '.join(str(rhs).split())
    if re.fullmatch(r'[A-Za-z_]\w*', text) and text in params:
        return text, None
    match = re.fullmatch(r'([A-Za-z_]\w*)\s*(?:\.|->)\s*([A-Za-z_]\w*)', text)
    if match and match.group(1) in params:
        return match.group(1), match.group(2)
    return None


def _matching_opcode(opcodes: list[dict[str, Any]], return_used: bool, arity: int) -> str | None:
    want_void = not return_used
    for signature in opcodes:
        if (signature['return_type'] == 'void') != want_void:
            continue
        if arity >= 0 and len(signature['parameters']) != arity:
            continue
        return str(signature['name'])
    return None


def _code_word_slots(sym_scope: dict[str, Any], guard: str, entries: list[str]) -> dict[str, list[dict[str, Any]]]:
    direct, static_group = _multi_direct(sym_scope, guard)
    dispatchers = _indirect_dispatchers(sym_scope, direct)
    if not dispatchers or any(entry not in dispatchers for entry in entries):
        return {}
    opcodes: list[dict[str, Any]] = []
    for name in direct:
        signature = _signature_for_cut(sym_scope, name, include_static=static_group)
        if signature is None or signature.get('linkage') == 'static':
            continue
        opcodes.append(signature)
    bodies = {
        name: body
        for _text, defined in _defining_sources(sym_scope, set(entries))
        for name, body, _static in defined
    }
    slots: dict[str, list[dict[str, Any]]] = {}
    for entry in entries:
        signature = _signature_for_cut(sym_scope, entry, include_static=True)
        body = bodies.get(entry, '')
        if signature is None or not body:
            continue
        params = {str(item['name']) for item in signature['parameters']}
        seen: set[tuple[str, str | None]] = set()
        entry_slots: list[dict[str, Any]] = []
        for site in _indirect_sites(body):
            rhs = _fed_from_local(
                body,
                str(site.get('rhs') or ''),
                params,
                int(site.get('rhs_at') or 0),
            )
            parsed = _stream_slot(rhs, params)
            if parsed is None or parsed in seen:
                continue
            seen.add(parsed)
            param, field = parsed
            entry_slots.append({
                'param': param,
                'field': field,
                'opcode': _matching_opcode(opcodes, bool(site.get('return_used')), int(site.get('arity', -1))),
            })
        if entry_slots:
            slots[entry] = entry_slots
    return slots


def _opcode_declarations(sym_scope: dict[str, Any],
                         functions: list[str]) -> tuple[list[str], list[dict[str, Any]]]:
    declarations: list[str] = []
    signatures: list[dict[str, Any]] = []
    seen: set[str] = set(functions)
    for slots in (sym_scope.get('code_word_slots') or {}).values():
        for slot in slots:
            name = str(slot.get('opcode') or '')
            if not name or name in seen:
                continue
            seen.add(name)
            signature = _signature_for_cut(sym_scope, name, include_static=True)
            if signature is None or signature.get('linkage') == 'static':
                continue
            signatures.append(signature)
            params = _declaration_params(signature)
            shown = str(signature.get('return_decl') or signature['return_type'])
            declarations.append(f'{shown} {name}({", ".join(params) if params else "void"});')
    return declarations, signatures


def _registration_corpus(path: Path, case_ir: dict[str, Any] | None) -> str:
    files: list[Path] = [path]
    if path.parent.is_dir():
        files.extend(path.parent.glob('*.h'))
    root = _source_root(case_ir)
    bases = [path.parent, path.parent.parent]
    if root is not None:
        bases.append(root)
        include_dir = root / 'include'
        if include_dir.is_dir():
            files.extend(include_dir.glob('*.h'))
        server = root / 'server'
        if server.is_dir():
            files.extend(server.glob('*.c'))
        includes = (((case_ir or {}).get('app_profile') or {}).get('builds') or {}).get('baseline', {}).get('include_dirs') or []
        for item in includes:
            base = Path(str(item))
            if base.is_dir():
                bases.append(base)
                files.extend(base.glob('*.h'))
    try:
        source = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        source = ''
    for include in re.findall(r'#\s*include\s+"([^"]+)"', source):
        for base in bases:
            files.append(base / include)
    chunks: list[str] = []
    seen: set[str] = set()
    for item in files:
        if not item.is_file():
            continue
        key = str(item.resolve()) if item.exists() else str(item)
        if key in seen:
            continue
        seen.add(key)
        try:
            chunks.append(item.read_text(encoding='utf-8', errors='replace'))
        except OSError:
            continue
    return '\n'.join(chunks)


def _definition_path(sym_scope: dict[str, Any],
                     function: str,
                     case_ir: dict[str, Any] | None) -> Path | None:
    for raw_path in sym_scope.get('slice_sources') or []:
        path = Path(str(raw_path))
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        if _function_definition_kind(text, function):
            return path
    root = _source_root(case_ir)
    if root is None:
        return None
    return locate_function_source(root, function)


def _call_target(sym_scope: dict[str, Any], function: str) -> tuple[str, dict[str, Any]] | None:
    found = _signature_for_cut(sym_scope, function, include_static=True)
    path: Path | None = None
    if found is None or found.get('linkage') == 'static':
        static_found, static_path = _static_signature_in_sources(sym_scope, function)
        if static_found is not None and static_path is not None:
            found = static_found
            path = static_path
    if found is None:
        return None
    if found.get('linkage') == 'static':
        if path is None:
            _found_path = _static_signature_in_sources(sym_scope, function)
            path = _found_path[1]
        if path is None:
            return None
        bound = dict(found)
        bound['call_name'] = f'__vg_export_{function}'
        _store_static_exports(sym_scope, [{
            'function': function,
            'file': str(path.resolve()),
            'source': render_static_export(bound),
        }])
        return bound['call_name'], bound
    return str(found.get('call_name') or found['name']), found


def _runner_source(signature: dict[str, Any],
                   callee: str,
                   callee_signature: dict[str, Any],
                   decline: str | None,
                   null_guard: bool) -> str:
    params = _declaration_params(signature)
    joined = ', '.join(params) if params else 'void'
    names = [str(item['name']) for item in signature['parameters']]
    args = ', '.join(names)
    shown = str(signature.get('return_decl') or signature['return_type'])
    callee_params = _declaration_params(callee_signature)
    callee_joined = ', '.join(callee_params) if callee_params else 'void'
    callee_shown = str(callee_signature.get('return_decl') or callee_signature['return_type'])
    prelude = f'{callee_shown} {callee}({callee_joined});\n'
    if signature['return_type'] == 'void':
        body = f'    {callee}({args});'
    elif null_guard and names:
        body = f'    if (!{names[0]}) return 0;\n    return {callee}({args});'
    elif decline:
        body = (
            f'    {signature["return_type"]} rv = {callee}({args});\n'
            f'    if (rv != {decline}) {{\n'
            f'        return rv;\n'
            f'    }}\n'
            f'    return {decline};'
        )
    else:
        body = f'    return {callee}({args});'
    return f'{prelude}{shown} {signature["name"]}({joined}) {{\n{body}\n}}\n'


def _store_runner(sym_scope: dict[str, Any],
                  signature: dict[str, Any],
                  source: str) -> str:
    stored = dict(sym_scope.get('synthetic_signatures') or {})
    stored[str(signature['name'])] = signature
    sym_scope['synthetic_signatures'] = stored
    runners = dict(sym_scope.get('hook_runners') or {})
    runners[str(signature['name'])] = source
    sym_scope['hook_runners'] = runners
    return str(signature['name'])


def _hook_entry(sym_scope: dict[str, Any],
                function: str,
                text: str,
                corpus: str) -> str | None:
    hooks = re.findall(
        rf'(?<![\w])ap_hook_([A-Za-z_]\w*)\s*\(\s*{re.escape(function)}\b',
        text,
    )
    hooks = list(dict.fromkeys(hooks))
    if len(hooks) != 1:
        return None
    hook = hooks[0]
    declared = re.search(
        rf'AP_DECLARE_HOOK\s*\(\s*([^,]+?)\s*,\s*{re.escape(hook)}\s*,\s*\(([^)]*)\)\s*\)',
        corpus,
    )
    if declared is None:
        return None
    ret = ' '.join(declared.group(1).split())
    params = ' '.join(declared.group(2).split())
    runner = f'ap_run_{hook}'
    signature = parse_c_function_signature(f'{ret} {runner}({params});', runner)
    preview = _signature_for_cut(sym_scope, function, include_static=True)
    if preview is None:
        preview, _path = _static_signature_in_sources(sym_scope, function)
    if signature is None or preview is None or len(signature['parameters']) != len(preview['parameters']):
        return None
    target = _call_target(sym_scope, function)
    if target is None:
        return None
    decline_match = re.search(
        rf'AP_IMPLEMENT_HOOK_RUN_FIRST\s*\([^)]*?{re.escape(hook)}\s*,\s*\([^)]*\)\s*,\s*\([^)]*\)\s*,\s*([A-Za-z_]\w*)\s*\)',
        corpus,
        re.S,
    )
    decline = decline_match.group(1) if decline_match else None
    source = _runner_source(signature, target[0], target[1], decline, False)
    return _store_runner(sym_scope, signature, source)


def _filter_entry(sym_scope: dict[str, Any], function: str, text: str, corpus: str) -> str | None:
    if not re.search(
        rf'(?<![\w])ap_register_output_filter(?:_protocol)?\s*\([^,]*,\s*{re.escape(function)}\b',
        text,
    ):
        return None
    signature = parse_c_function_signature(corpus, 'ap_pass_brigade')
    preview = _signature_for_cut(sym_scope, function, include_static=True)
    if preview is None:
        preview, _path = _static_signature_in_sources(sym_scope, function)
    if preview is None:
        return None
    if signature is not None and len(signature['parameters']) != len(preview['parameters']):
        return None
    target = _call_target(sym_scope, function)
    if target is None:
        return None
    if signature is None:
        signature = dict(target[1])
        signature['name'] = 'ap_pass_brigade'
        signature['linkage'] = 'global'
        signature.pop('call_name', None)
    source = _runner_source(signature, target[0], target[1], None, True)
    return _store_runner(sym_scope, signature, source)


def _assigned_slot(text: str, function: str) -> str | None:
    slots = list(dict.fromkeys(re.findall(
        rf'(?<![\w.>-])([A-Za-z_]\w*)\s*=\s*{re.escape(function)}\s*;',
        _strip_c_comments(text),
    )))
    if len(slots) != 1:
        return None
    return slots[0]


def _callers_of_slot(slot: str, function: str, files: list[Path]) -> list[tuple[str, Path]]:
    callers: list[tuple[str, Path]] = []
    seen_files: set[str] = set()
    seen_names: set[str] = set()
    for item in files:
        if not item.is_file():
            continue
        key = str(item.resolve()) if item.exists() else str(item)
        if key in seen_files:
            continue
        seen_files.add(key)
        try:
            item_text = item.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        if slot not in item_text:
            continue
        expanded = _expand_definition_macros(item, item_text)
        for name, body, _static in _defined_functions(expanded):
            if name == function or name in seen_names:
                continue
            if _body_calls(body, slot):
                callers.append((name, item))
                seen_names.add(name)
                if len(callers) > 1:
                    return callers
    return callers


def _unique_slot_caller(path: Path,
                        text: str,
                        function: str,
                        case_ir: dict[str, Any] | None) -> tuple[str, Path] | None:
    slot = _assigned_slot(text, function)
    if slot is None:
        return None
    local = sorted(path.parent.glob('*.c')) if path.parent.is_dir() else []
    callers = _callers_of_slot(slot, function, local)
    if not callers:
        root = _source_root(case_ir)
        if root is not None and root.is_dir():
            distant = [
                item for item in root.rglob('*.c')
                if item.is_file() and item.parent != path.parent
            ]
            callers = _callers_of_slot(slot, function, distant)
    if len(callers) != 1:
        return None
    return callers[0]


def _slot_entry(sym_scope: dict[str, Any],
                function: str,
                path: Path,
                text: str,
                case_ir: dict[str, Any] | None) -> str | None:
    found = _unique_slot_caller(path, text, function, case_ir)
    if found is None:
        return None
    caller, caller_path = found
    if str(caller_path.resolve()) not in {
        str(Path(str(raw)).resolve())
        for raw in sym_scope.get('slice_sources') or []
        if Path(str(raw)).exists()
    }:
        return None
    slot = _assigned_slot(text, function)
    target = _call_target(sym_scope, function)
    if target is None or _signature_for_cut(sym_scope, caller) is None:
        return None
    links = list(sym_scope.get('slot_links') or [])
    links.append({
        'slot': slot,
        'target': target[0],
        'target_signature': target[1],
        'callee_decl': _function_declarator(
            target[1], target[0], ', '.join(_declaration_params(target[1])),
        ) + ';',
    })
    sym_scope['slot_links'] = links
    return caller


def _drop_calling_macros(text: str) -> str:
    words = text.split()
    kept = [
        word for word in words
        if not (word.isupper() and word.endswith(('API', 'CALL', 'FUN', 'DECLARE', 'EXPORT')))
    ]
    if not kept or len(kept) == len(words):
        return ' '.join(words)
    return ' '.join(kept)


def _declaration_at(text: str, function: str) -> dict[str, Any] | None:
    stripped = _strip_c_comments(text)
    pattern = re.compile(rf'(?<![\w#]){re.escape(function)}\s*\(')
    for match in pattern.finditer(stripped):
        close = _proto_match(stripped, match.end() - 1, '(', ')')
        if close < 0:
            continue
        cursor = close + 1
        while cursor < len(stripped) and stripped[cursor].isspace():
            cursor += 1
        if cursor >= len(stripped) or stripped[cursor] != ';':
            continue
        raw_header = stripped[_header_start(stripped, match.start()):match.start()]
        if '=' in raw_header:
            continue
        raw_header = '\n'.join(
            line for line in raw_header.splitlines()
            if not line.strip().startswith('#')
        )
        raw_header = _unwrap_decl_macros(raw_header)
        return_decl = _drop_calling_macros(_decl_type_text(raw_header))
        if not re.fullmatch(
            r'(?:(?:const|struct|union|enum|unsigned|signed|long|short|int|char|void)\s+)*[A-Za-z_]\w*(?:\s*\*)*',
            return_decl,
        ):
            continue
        params: list[dict[str, str]] = []
        failed = False
        for raw in _split_signature_params(stripped[match.end():close]):
            if raw in {'void', '...'}:
                continue
            name_match = re.search(r'([A-Za-z_]\w*)\s*$', ' '.join(raw.split()))
            if name_match is None:
                failed = True
                break
            shown = ' '.join(raw.split())
            type_text = _drop_calling_macros(_clean_type_text(shown[:name_match.start()]))
            params.append({'name': name_match.group(1), 'type_text': type_text, 'raw': shown})
        if failed:
            continue
        joined = ', '.join(item['raw'] for item in params) if params else 'void'
        return {
            'return_decl': return_decl,
            'parameters': params,
            'declarator': f'{return_decl} {function}({joined})',
        }
    return None


def _struct_pointer_param(type_text: str) -> bool:
    words = type_text.replace('*', ' ').split()
    if not words or words == ['void']:
        return False
    return '*' in type_text or words[-1].endswith('Ptr')


def _external_declaration(path: Path,
                          case_ir: dict[str, Any] | None,
                          name: str) -> dict[str, Any] | None:
    found = _declaration_at(_registration_corpus(path, case_ir), name)
    if found is not None:
        return found
    roots: list[Path] = []
    root = _source_root(case_ir)
    if root is not None:
        roots.append(root / 'include')
    includes = (((case_ir or {}).get('app_profile') or {}).get('symbolic_slice') or {}).get('include_dirs') or []
    if not includes:
        includes = (((case_ir or {}).get('app_profile') or {}).get('builds') or {}).get('baseline', {}).get('include_dirs') or []
    roots.extend(Path(str(item)) for item in includes)
    seen: set[str] = set()
    for base in roots:
        if not base.is_dir():
            continue
        for header in base.rglob('*.h'):
            key = str(header.resolve()) if header.exists() else str(header)
            if key in seen or not header.is_file():
                continue
            seen.add(key)
            try:
                text = header.read_text(encoding='utf-8', errors='replace')
            except OSError:
                continue
            if name not in text:
                continue
            found = _declaration_at(text, name)
            if found is not None:
                return found
    return None


def _call_struct_sites(body: str, base: str, arrow: bool) -> list[tuple[str, int]]:
    token = ''.join(base.split()) if arrow else f'&{base}'
    sites: list[tuple[str, int]] = []
    pattern = re.compile(r'(?<![\w])([A-Za-z_]\w*)\s*\(')
    for match in pattern.finditer(body):
        callee = match.group(1)
        if callee in {'if', 'for', 'while', 'switch', 'return', 'sizeof', 'defined'}:
            continue
        close = _proto_match(body, match.end() - 1, '(', ')')
        if close < 0:
            continue
        for index, raw in enumerate(_split_signature_params(body[match.end():close])):
            if ''.join(raw.split()) == token:
                sites.append((callee, index))
                break
    return sites


def _dispatch_source(declarator: str,
                     return_decl: str,
                     struct_name: str,
                     user_name: str | None,
                     target: str,
                     target_signature: dict[str, Any]) -> str:
    lines: list[str] = []
    arguments: list[str] = []
    used_user = False
    for item in target_signature['parameters']:
        shown = str(item.get('decl_type') or item.get('type_text') or '')
        pointer = item.get('kind') in {'pointer', 'buffer'} or '*' in shown
        if pointer and not used_user and user_name:
            arguments.append(user_name)
            used_user = True
            continue
        if pointer:
            local = f'{item["name"]}_buf'
            stored, argument = _pointer_storage(item, local)
            lines.extend(stored)
            arguments.append(argument)
            used_user = True
            continue
        arguments.append('0')
    body = '\n'.join(f'    {line}' for line in lines)
    call = f'        {target}({", ".join(arguments)});'
    if body:
        call = body + '\n' + call
    tail = '' if return_decl.strip() == 'void' else '    return 0;\n'
    shown = str(target_signature.get('return_decl') or target_signature['return_type'])
    params = ', '.join(_declaration_params(target_signature)) or 'void'
    return (
        f'{shown} {target}({params});\n'
        f'{declarator} {{\n'
        f'    if ({struct_name}) {{\n'
        f'{call}\n'
        f'    }}\n'
        f'{tail}}}'
    )


def _field_entry(sym_scope: dict[str, Any],
                 function: str,
                 path: Path,
                 text: str,
                 case_ir: dict[str, Any] | None) -> str | None:
    stripped = _strip_c_comments(text)
    stores = list(dict.fromkeys(re.findall(
        rf'(?<![\w])([A-Za-z_]\w*)\s*(\.|->)\s*([A-Za-z_]\w*)\s*=\s*{re.escape(function)}\s*;',
        stripped,
    )))
    if len(stores) != 1:
        return None
    base, arrow, _field = stores[0]
    expanded = _expand_definition_macros(path, text)
    defined = _defined_functions(expanded)
    defined_names = {name for name, _body, _static in defined}
    sites: list[tuple[str, str, int]] = []
    for name, body, _static in defined:
        if name == function:
            continue
        for callee, index in _call_struct_sites(body, base, arrow == '->'):
            if callee == function or callee in defined_names:
                continue
            sites.append((name, callee, index))
    grouped = list(dict.fromkeys(sites))
    declarations: dict[str, dict[str, Any] | None] = {}
    kept: list[tuple[str, str, int]] = []
    for name, callee, index in grouped:
        if callee not in declarations:
            declarations[callee] = _external_declaration(path, case_ir, callee)
        declaration = declarations[callee]
        if declaration is None or index >= len(declaration['parameters']):
            continue
        if not _struct_pointer_param(declaration['parameters'][index]['type_text']):
            continue
        kept.append((name, callee, index))
    callers = list(dict.fromkeys(item[0] for item in kept))
    callees = list(dict.fromkeys(item[1] for item in kept))
    if len(callers) != 1 or len(callees) != 1:
        return None
    caller, callee = callers[0], callees[0]
    indexes = {index for name, called, index in kept if name == caller and called == callee}
    if len(indexes) != 1:
        return None
    index = indexes.pop()
    declaration = declarations[callee]
    if declaration is None:
        return None
    user_name = None
    if index + 1 < len(declaration['parameters']):
        user = declaration['parameters'][index + 1]
        if '*' in user['type_text'] or user['type_text'].endswith('Ptr'):
            user_name = user['name']
    target = _call_target(sym_scope, function)
    if target is None:
        return None
    corpus = _registration_corpus(path, case_ir)
    entry = _filter_entry(sym_scope, caller, text, corpus) or _hook_entry(sym_scope, caller, text, corpus)
    if entry is None:
        if _signature_for_cut(sym_scope, caller, include_static=True) is None:
            return None
        entry = caller
    includes = ''.join(
        f'#include {item}\n'
        for item in dict.fromkeys(re.findall(r'(<libxml/[^>]+>)', text))
    )
    source = _dispatch_source(
        declaration['declarator'],
        declaration['return_decl'],
        declaration['parameters'][index]['name'],
        user_name,
        target[0],
        target[1],
    )
    stored = list(sym_scope.get('field_dispatches') or [])
    stored.append({'includes': includes, 'source': source})
    sym_scope['field_dispatches'] = stored
    return entry


_FIELD_CALLER_CACHE: dict[tuple[str, str, str], tuple[str, str, str] | None] = {}


def _stored_fields(text: str, function: str) -> list[str]:
    found = re.findall(
        rf'(?<![\w])[A-Za-z_]\w*\s*(?:\.|->)\s*([A-Za-z_]\w*)\s*=\s*{re.escape(function)}\s*;',
        _strip_c_comments(text),
    )
    return list(dict.fromkeys(found))


def _callers_of_field(field: str, function: str, files: list[Path], limit: int = 2) -> list[tuple[str, Path]]:
    pattern = re.compile(rf'(?:->|\.)\s*{re.escape(field)}\s*\(')
    callers: list[tuple[str, Path]] = []
    seen_files: set[str] = set()
    seen_names: set[str] = set()
    for item in files:
        if not item.is_file():
            continue
        key = str(item.resolve()) if item.exists() else str(item)
        if key in seen_files:
            continue
        seen_files.add(key)
        try:
            item_text = item.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        if not pattern.search(item_text):
            continue
        expanded = _expand_definition_macros(item, item_text)
        macros = _subst_macros(item)
        for name, body, _static in _defined_functions(expanded):
            if name == function or name in seen_names:
                continue
            if pattern.search(_apply_subst_macros(body, macros)):
                callers.append((name, item))
                seen_names.add(name)
                if len(callers) >= limit:
                    return callers
    return callers


def _unique_field_caller(path: Path,
                         text: str,
                         function: str,
                         case_ir: dict[str, Any] | None) -> tuple[str, Path, str] | None:
    fields = _stored_fields(text, function)
    if len(fields) != 1:
        return None
    root = _source_root(case_ir)
    root_key = str(root.resolve()) if root is not None and root.exists() else ''
    if not root_key:
        root_key = 'slice:' + '\n'.join(str(item.resolve()) for item in _slice_c_files(case_ir))
    key = (
        str(path.resolve()) if path.exists() else str(path),
        function,
        root_key,
    )
    cached = _FIELD_CALLER_CACHE.get(key, False)
    if cached is not False:
        if cached is None:
            return None
        return cached[0], Path(cached[1]), cached[2]
    field = fields[0]
    local = sorted(path.parent.glob('*.c')) if path.parent.is_dir() else []
    callers = _callers_of_field(field, function, local)
    if not callers and root is not None and root.is_dir():
        distant = [
            item for item in root.rglob('*.c')
            if item.is_file() and item.parent != path.parent
        ]
        callers = _callers_of_field(field, function, distant)
    if not callers and root is None:
        distant = [
            item for item in _slice_c_files(case_ir)
            if item.is_file() and item.parent != path.parent
        ]
        callers = _callers_of_field(field, function, distant)
    if len(callers) != 1:
        _FIELD_CALLER_CACHE[key] = None
        return None
    caller, caller_path = callers[0]
    stored = (caller, str(caller_path.resolve()) if caller_path.exists() else str(caller_path), field)
    _FIELD_CALLER_CACHE[key] = stored
    return caller, caller_path, field


def _parameter_object(signature: dict[str, Any], name: str) -> bool:
    for item in signature['parameters']:
        if str(item.get('name') or '') != name:
            continue
        shown = str(item.get('decl_type') or item.get('type_text') or '')
        return '*' in shown or 'struct' in shown
    return False


def _field_has_array(texts: list[str], type_name: str, field: str) -> bool:
    tag = type_name
    for text in texts:
        alias = re.search(
            rf'typedef\s+struct\s+([A-Za-z_]\w*)\s+{re.escape(type_name)}\s*;',
            text,
        )
        if alias:
            tag = alias.group(1)
            break
    bodies: list[str] = []
    named = (
        rf'typedef\s+struct\s+{re.escape(tag)}\s*\{{',
        rf'struct\s+{re.escape(tag)}\s*\{{',
    )
    for raw in texts:
        text = _strip_c_comments(raw)
        for pattern in named:
            for match in re.finditer(pattern, text):
                end = _match_code_brace(text, match.end() - 1)
                if end > match.end():
                    bodies.append(text[match.end():end])
    field_pattern = re.compile(rf'\b{re.escape(field)}\s*\[')
    return any(field_pattern.search(fragment) for body in bodies for fragment in body.split(';'))


def _seed_field_chain(signature: dict[str, Any],
                     texts: list[str],
                     param: str,
                     hops: list[str | tuple[str, str]],
                     field: str,
                     target: str,
                     local_type: str | None = None) -> tuple[list[str], str] | None:
    if not hops:
        return None
    owner = next((item for item in signature['parameters'] if str(item.get('name') or '') == param), None)
    pointee = str((owner or {}).get('pointee') or '').split()
    if not pointee or not _parameter_object(signature, param):
        return None
    current = pointee[-1]
    slot_types: list[str] = []
    slots: list[str] = []
    cursor = f'{param}_obj'
    links: list[str] = []
    last_type = ''
    last_pointer = False
    embedded_type = ''
    for hop in hops:
        if isinstance(hop, tuple):
            operator, hop_name = hop
        else:
            operator, hop_name = '->', str(hop)
        field_type = _struct_field_type(texts, current, hop_name)
        if not field_type or _field_has_array(texts, current, hop_name):
            return None
        shown = ' '.join(str(field_type).split())
        if operator == '->':
            if not shown.endswith('*'):
                return None
            slot_type = shown[:-1].strip()
            slot = f'{hop_name}_slot'
            slot_types.append(slot_type)
            slots.append(slot)
            links.append(f'    {cursor}.{hop_name} = &{slot};')
            cursor = slot
            last_type = shown
            last_pointer = True
            current = shown.replace('*', ' ').split()[-1]
            continue
        if operator != '.' or shown.endswith('*'):
            return None
        cursor = f'{cursor}.{hop_name}'
        last_pointer = False
        embedded_type = shown
        current = shown.replace('*', ' ').split()[-1]
    if len(slots) + sum(1 for hop in hops if (hop[0] if isinstance(hop, tuple) else '->') == '.') < 1:
        return None
    if not any((hop[0] if isinstance(hop, tuple) else '->') == '.' for hop in hops) and len(slots) < 2:
        return None
    if local_type is not None:
        if last_pointer:
            if last_type != f'{local_type} *':
                return None
        elif embedded_type != local_type:
            return None
    assign = f'    {cursor}.{field} = {target};'
    rows = [f'    {slot_type} {slot};' for slot_type, slot in zip(slot_types, slots)]
    rows.extend(f'    memset(&{slot}, 0, sizeof({slot}));' for slot in slots)
    rows.append(assign)
    rows.extend(links)
    return rows, assign


def _pointer_array_bound(texts: list[str], type_name: str, field: str) -> tuple[str, int] | None:
    tag = type_name
    for text in texts:
        alias = re.search(
            rf'typedef\s+struct\s+([A-Za-z_]\w*)\s+{re.escape(type_name)}\s*;',
            text,
        )
        if alias:
            tag = alias.group(1)
            break
    bodies: list[str] = []
    named = (
        rf'typedef\s+struct\s+{re.escape(tag)}\s*\{{',
        rf'struct\s+{re.escape(tag)}\s*\{{',
    )
    for raw in texts:
        text = _strip_c_comments(raw)
        for pattern in named:
            for match in re.finditer(pattern, text):
                end = _match_code_brace(text, match.end() - 1)
                if end > match.end():
                    bodies.append(text[match.end():end])
    field_pattern = re.compile(
        rf'([A-Za-z_][\w\s\*]*)\b{re.escape(field)}\b\s*\[\s*(\d+)\s*\]'
    )
    for body in bodies:
        for fragment in body.split(';'):
            match = field_pattern.search(fragment)
            if not match:
                continue
            shown = ' '.join(match.group(1).split())
            length = int(match.group(2))
            if not shown.rstrip().endswith('*') or length < 1 or length > 16:
                return None
            return shown.rstrip()[:-1].strip(), length
    return None


def _seed_indexed_pointer(signature: dict[str, Any],
                          texts: list[str],
                          field: str,
                          target: str,
                          indexed: tuple[str, str, int]) -> tuple[list[str], str] | None:
    param, member, index = indexed
    owner = next((item for item in signature['parameters'] if str(item.get('name') or '') == param), None)
    pointee = str((owner or {}).get('pointee') or '').split()
    if not pointee or not _parameter_object(signature, param):
        return None
    bound = _pointer_array_bound(texts, pointee[-1], member)
    if bound is None:
        return None
    element_type, length = bound
    if index < 0 or index >= length:
        return None
    slot = f'{member}_slot'
    assign = f'    {slot}.{field} = {target};'
    return [
        f'    {element_type} {slot};',
        f'    memset(&{slot}, 0, sizeof({slot}));',
        assign,
        f'    {param}_obj.{member}[{index}] = &{slot};',
    ], assign


def _strip_pointer_casts(body: str) -> str:
    pattern = re.compile(
        r'\(\s*(?:const\s+)?(?:struct\s+|union\s+|enum\s+)?[A-Za-z_]\w*(?:\s*\*+\s*)+\)\s*'
    )
    current = body
    for _step in range(8):
        updated = pattern.sub('', current)
        if updated == current:
            return current
        current = updated
    return current


def _collapse_deref_dots(body: str) -> str:
    pattern = re.compile(
        r'\(\s*\*\s*((?:[A-Za-z_]\w*\s*->\s*)*[A-Za-z_]\w*)\s*\)\s*\.'
    )
    current = body
    for _step in range(8):
        updated = pattern.sub(lambda match: match.group(1) + '->', current)
        if updated == current:
            return current
        current = updated
    return current


def _seed_bounded_field_chain(body: str,
                              signature: dict[str, Any],
                              texts: list[str] | None,
                              field: str,
                              target: str,
                              base: str) -> tuple[str, list[str], str] | None:
    if not texts:
        return None
    parameters = {str(item.get('name') or '') for item in signature['parameters']}
    hop = r'\s*(?:->|\.)\s*[A-Za-z_]\w*'
    long = re.findall(
        rf'(?<![\w>-])([A-Za-z_]\w*(?:{hop}){{9,}})\s*\)?\s*(?:->|\.)\s*{re.escape(field)}\s*\(',
        body,
    )
    for text in long:
        names = re.findall(r'[A-Za-z_]\w*', text)
        if names and names[0] in parameters:
            return ('reject', [], '')
    calls = re.findall(
        rf'(?<![\w>-])([A-Za-z_]\w*(?:{hop}){{1,8}}\s*(?:->|\.)\s*{re.escape(field)})\s*\(',
        body,
    )
    chosen: list[tuple[str, ...]] = []
    parsed: dict[tuple[str, ...], list[tuple[str, str]]] = {}
    for text in calls:
        parts = re.split(r'\s*(->|\.)\s*', text)
        if not parts or parts[0] not in parameters or len(parts) < 5 or len(parts) % 2 == 0:
            continue
        if parts[-1] != field:
            continue
        hop_names = parts[2:-1:2]
        storage = parts[3::2]
        if not hop_names or hop_names[-1] != base or len(storage) != len(hop_names):
            continue
        steps = list(zip(storage, hop_names))
        if all(operator == '->' for operator, _name in steps) and len(steps) < 2:
            continue
        key = tuple(parts)
        chosen.append(key)
        parsed[key] = steps
    if len(set(chosen)) > 1:
        return ('reject', [], '')
    if len(set(chosen)) == 1:
        key = chosen[0]
        seeded = _seed_field_chain(signature, texts, key[0], parsed[key], field, target)
        if seeded is None:
            return ('reject', [], '')
        return ('seed', seeded[0], seeded[1])
    local_matches = list(re.finditer(
        rf'(?<![\w]){re.escape(base)}\s*=\s*(&)?\s*\(?\s*([A-Za-z_]\w*(?:{hop}){{1,8}})\s*\)?\s*;',
        body,
    ))
    local_rows: list[tuple[str, ...]] = []
    local_steps: dict[tuple[str, ...], list[tuple[str, str]]] = {}
    for match in local_matches:
        text = match.group(2)
        parts = re.split(r'\s*(->|\.)\s*', text)
        if not parts or parts[0] not in parameters or len(parts) < 3 or len(parts) % 2 == 0:
            continue
        names = parts[2::2]
        leading = parts[1::2]
        if not names or len(leading) != len(names):
            continue
        steps: list[tuple[str, str]] = []
        for index, hop_name in enumerate(names):
            if index < len(names) - 1:
                operator = leading[index + 1]
            else:
                operator = '.' if match.group(1) else '->'
            steps.append((operator, hop_name))
        if all(operator == '->' for operator, _name in steps) and len(steps) < 2:
            continue
        key = (parts[0], tuple(steps), bool(match.group(1)))
        local_rows.append(key)
        local_steps[key] = steps
    if len(set(local_rows)) != 1:
        return None
    key = local_rows[0]
    seeded = _seed_field_chain(
        signature,
        texts,
        key[0],
        local_steps[key],
        field,
        target,
        _local_pointer_type(body, base),
    )
    if seeded is None:
        return ('reject', [], '')
    return ('seed', seeded[0], seeded[1])


def _handler_seed(body: str,
                  signature: dict[str, Any],
                  field: str,
                  target: str,
                  texts: list[str] | None = None) -> tuple[list[str], str] | None:
    body = _collapse_deref_dots(_strip_pointer_casts(body))
    index_uses = re.findall(
        rf'\[([^\]]*)\]\s*\)?\s*(?:->|\.)\s*{re.escape(field)}\s*\(',
        body,
    )
    if index_uses:
        if any(not item.strip().isdigit() for item in index_uses) or not texts:
            return None
        calls = re.findall(
            rf'(?<![\w])\(?\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*\[\s*(\d+)\s*\]\s*\)?\s*(?:->|\.)\s*{re.escape(field)}\s*\(',
            body,
        )
        unique = {(param, member, int(index)) for param, member, index in calls}
        if len(unique) != 1:
            return None
        return _seed_indexed_pointer(signature, texts, field, target, unique.pop())
    bases = re.findall(
        rf'(?<![\w])\(?\s*([A-Za-z_]\w*)\s*\)?\s*(?:->|\.)\s*{re.escape(field)}\s*\(',
        body,
    )
    if len(set(bases)) != 1:
        return None
    base = bases[0]
    if base in {str(item.get('name') or '') for item in signature['parameters']}:
        if not _parameter_object(signature, base):
            return None
        assign = f'    {base}_obj.{field} = {target};'
        return [assign], assign
    wrapped = re.findall(
        rf'(?<![\w])([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*\)\s*(?:->|\.)\s*{re.escape(field)}\s*\(',
        body,
    )
    if len(set(wrapped)) == 1 and wrapped[0][1] == base and texts:
        param, member = wrapped[0]
        owner = next((item for item in signature['parameters'] if str(item.get('name') or '') == param), None)
        pointee = str((owner or {}).get('pointee') or '').split()
        field_type = _struct_field_type(texts, pointee[-1], member) if pointee and _parameter_object(signature, param) else None
        if field_type and field_type.rstrip().endswith('*'):
            slot_type = field_type.rstrip()[:-1].strip()
            slot = f'{member}_slot'
            assign = f'    {slot}.{field} = {target};'
            return [
                f'    {slot_type} {slot};',
                f'    memset(&{slot}, 0, sizeof({slot}));',
                assign,
                f'    {param}_obj.{member} = &{slot};',
            ], assign
    direct_one = re.findall(
        rf'(?<![\w>-])([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*{re.escape(field)}\s*\(',
        body,
    )
    parameter_names = {str(item.get('name') or '') for item in signature['parameters']}
    owned = [item for item in direct_one if item[0] in parameter_names and item[1] == base]
    if len(set(owned)) == 1 and texts:
        param, member = owned[0]
        owner = next((item for item in signature['parameters'] if str(item.get('name') or '') == param), None)
        pointee = str((owner or {}).get('pointee') or '').split()
        field_type = _struct_field_type(texts, pointee[-1], member) if pointee and _parameter_object(signature, param) else None
        if field_type and field_type.rstrip().endswith('*'):
            slot_type = field_type.rstrip()[:-1].strip()
            slot = f'{member}_slot'
            assign = f'    {slot}.{field} = {target};'
            return [
                f'    {slot_type} {slot};',
                f'    memset(&{slot}, 0, sizeof({slot}));',
                assign,
                f'    {param}_obj.{member} = &{slot};',
            ], assign
    assignments = re.findall(
        rf'(?<![\w]){re.escape(base)}\s*=\s*\(?\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*\)?\s*;',
        body,
    )
    writes = re.findall(rf'(?<![\w]){re.escape(base)}\s*=', body)
    if len(assignments) != 1 or len(writes) != 1:
        chain = re.findall(
            rf'(?<![\w]){re.escape(base)}\s*=\s*\(?\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*\)?\s*;',
            body,
        )
        if len(chain) != 1 or len(writes) != 1 or not texts:
            bounded = _seed_bounded_field_chain(body, signature, texts, field, target, base)
            if bounded is not None:
                if bounded[0] == 'reject':
                    return None
                return bounded[1], bounded[2]
            five = re.findall(
                rf'(?<![\w])([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*\)?\s*->\s*{re.escape(field)}\s*\(',
                body,
            )
            if len(set(five)) == 1 and five[0][5] == base and texts:
                seeded = _seed_field_chain(
                    signature, texts, five[0][0], list(five[0][1:]), field, target,
                )
                if seeded is not None:
                    return seeded
            local_five = re.findall(
                rf'(?<![\w]){re.escape(base)}\s*=\s*\(?\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*\)?\s*;',
                body,
            )
            if len(local_five) == 1 and len(writes) == 1 and texts:
                seeded = _seed_field_chain(
                    signature,
                    texts,
                    local_five[0][0],
                    list(local_five[0][1:]),
                    field,
                    target,
                    _local_pointer_type(body, base),
                )
                if seeded is not None:
                    return seeded
            four = re.findall(
                rf'(?<![\w])([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*\)?\s*->\s*{re.escape(field)}\s*\(',
                body,
            )
            if len(set(four)) == 1 and four[0][4] == base and texts:
                seeded = _seed_field_chain(
                    signature, texts, four[0][0], list(four[0][1:]), field, target,
                )
                if seeded is not None:
                    return seeded
            local_four = re.findall(
                rf'(?<![\w]){re.escape(base)}\s*=\s*\(?\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*\)?\s*;',
                body,
            )
            if len(local_four) == 1 and len(writes) == 1 and texts:
                seeded = _seed_field_chain(
                    signature,
                    texts,
                    local_four[0][0],
                    list(local_four[0][1:]),
                    field,
                    target,
                    _local_pointer_type(body, base),
                )
                if seeded is not None:
                    return seeded
            longer = re.findall(
                rf'(?<![\w])([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*\)?\s*->\s*{re.escape(field)}\s*\(',
                body,
            )
            if len(set(longer)) == 1 and longer[0][3] == base and texts:
                seeded = _seed_field_chain(
                    signature, texts, longer[0][0], list(longer[0][1:]), field, target,
                )
                if seeded is not None:
                    return seeded
            local_chain = re.findall(
                rf'(?<![\w]){re.escape(base)}\s*=\s*\(?\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*\)?\s*;',
                body,
            )
            if len(local_chain) == 1 and len(writes) == 1 and texts:
                seeded = _seed_field_chain(
                    signature,
                    texts,
                    local_chain[0][0],
                    list(local_chain[0][1:]),
                    field,
                    target,
                    _local_pointer_type(body, base),
                )
                if seeded is not None:
                    return seeded
            direct = re.findall(
                rf'(?<![\w])([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*\)?\s*->\s*{re.escape(field)}\s*\(',
                body,
            )
            if len(set(direct)) != 1 or direct[0][2] != base or not texts:
                return None
            param, mid, member = direct[0]
            owner = next((item for item in signature['parameters'] if str(item.get('name') or '') == param), None)
            pointee = str((owner or {}).get('pointee') or '').split()
            if not pointee or not _parameter_object(signature, param):
                return None
            mid_type = _struct_field_type(texts, pointee[-1], mid)
            if not mid_type or not mid_type.rstrip().endswith('*'):
                return None
            mid_name = mid_type.replace('*', ' ').split()[-1]
            member_type = _struct_field_type(texts, mid_name, member)
            if not member_type or not member_type.rstrip().endswith('*'):
                return None
            mid_slot = f'{mid}_slot'
            member_slot = f'{member}_slot'
            assign = f'    {member_slot}.{field} = {target};'
            return [
                f'    {mid_type.rstrip()[:-1].strip()} {mid_slot};',
                f'    {member_type.rstrip()[:-1].strip()} {member_slot};',
                f'    memset(&{mid_slot}, 0, sizeof({mid_slot}));',
                f'    memset(&{member_slot}, 0, sizeof({member_slot}));',
                assign,
                f'    {mid_slot}.{member} = &{member_slot};',
                f'    {param}_obj.{mid} = &{mid_slot};',
            ], assign
        param, mid, member = chain[0]
        owner = next((item for item in signature['parameters'] if str(item.get('name') or '') == param), None)
        pointee = str((owner or {}).get('pointee') or '').split()
        if not pointee or not _parameter_object(signature, param):
            return None
        mid_type = _struct_field_type(texts, pointee[-1], mid)
        if not mid_type or not mid_type.rstrip().endswith('*'):
            return None
        mid_name = mid_type.replace('*', ' ').split()[-1]
        member_type = _struct_field_type(texts, mid_name, member)
        local_type = _local_pointer_type(body, base)
        if not member_type or not member_type.rstrip().endswith('*') or not local_type:
            return None
        if ' '.join(member_type.split()) != f'{local_type} *':
            return None
        mid_slot = f'{mid}_slot'
        member_slot = f'{member}_slot'
        assign = f'    {member_slot}.{field} = {target};'
        return [
            f'    {mid_type.rstrip()[:-1].strip()} {mid_slot};',
            f'    {member_type.rstrip()[:-1].strip()} {member_slot};',
            f'    memset(&{mid_slot}, 0, sizeof({mid_slot}));',
            f'    memset(&{member_slot}, 0, sizeof({member_slot}));',
            assign,
            f'    {mid_slot}.{member} = &{member_slot};',
            f'    {param}_obj.{mid} = &{mid_slot};',
        ], assign
    param, member = assignments[0]
    if not _parameter_object(signature, param):
        return None
    types = re.findall(
        rf'(?:const\s+)?(?:(struct|union|enum)\s+)?([A-Za-z_]\w*)\s*\*\s*{re.escape(base)}\b',
        body,
    )
    if len(types) != 1:
        return None
    kind_word, type_name = types[0]
    type_text = f'{kind_word} {type_name}' if kind_word else type_name
    slot = f'{base}_slot'
    assign = f'    {slot}.{field} = {target};'
    return [
        f'    {type_text} {slot};',
        f'    memset(&{slot}, 0, sizeof({slot}));',
        assign,
        f'    {param}_obj.{member} = &{slot};',
    ], assign


def _logical_source(text: str) -> str:
    lines: list[str] = []
    pending = ''
    for line in text.splitlines():
        if line.rstrip().endswith('\\'):
            pending += line.rstrip()[:-1] + ' '
            continue
        lines.append(pending + line)
        pending = ''
    if pending:
        lines.append(pending)
    return '\n'.join(lines)


def _subst_macros(path: Path) -> dict[str, tuple[list[str], str]]:
    texts = []
    try:
        texts.append(path.read_text(encoding='utf-8', errors='replace'))
    except OSError:
        return {}
    if path.parent.is_dir():
        for header in sorted(path.parent.glob('*.h')):
            try:
                texts.append(header.read_text(encoding='utf-8', errors='replace'))
            except OSError:
                continue
    found: dict[str, tuple[list[str], str]] = {}
    pattern = re.compile(
        r'^[ \t]*#\s*define\s+([A-Za-z_]\w*)\s*\(\s*([A-Za-z_]\w*(?:\s*,\s*[A-Za-z_]\w*)*)\s*\)\s+(.+)$',
        re.M,
    )
    for text in texts:
        for match in pattern.finditer(_logical_source(text)):
            params = [item.strip() for item in match.group(2).split(',')]
            found[match.group(1)] = (params, match.group(3).strip())
    return found


def _apply_subst_macros(text: str, macros: dict[str, tuple[list[str], str]]) -> str:
    if not macros:
        return text
    pattern = re.compile(
        r'(?<![\w#])(' + '|'.join(re.escape(name) for name in macros) + r')\s*\(([^()]*)\)'
    )
    for _depth in range(8):
        def replace(match: re.Match[str]) -> str:
            params, body = macros[match.group(1)]
            args = [item.strip() for item in match.group(2).split(',')]
            if len(args) != len(params) or any(not arg for arg in args):
                return match.group(0)
            rewritten = body
            for param, arg in sorted(zip(params, args), key=lambda item: len(item[0]), reverse=True):
                rewritten = re.sub(rf'(?<![\w]){re.escape(param)}(?![\w])', arg, rewritten)
            return rewritten

        updated = pattern.sub(replace, text)
        if updated == text:
            break
        text = updated
    return text


def _strip_c_cast(expr: str) -> str:
    text = ' '.join(expr.split())
    while True:
        match = re.match(
            r'^\(\s*((?:const\s+)?(?:struct\s+|union\s+|enum\s+)?[A-Za-z_]\w*(?:\s*\*)*)\s*\)\s*(.+)$',
            text,
        )
        if not match:
            return text
        inside, rest = match.group(1).strip(), match.group(2).strip()
        if '*' not in inside and not inside.startswith(('struct ', 'union ', 'enum ', 'const ')) and rest.startswith(('->', '.')):
            return text
        text = rest


def _struct_field_type(texts: list[str], type_name: str, field: str) -> str | None:
    tag = type_name
    for text in texts:
        alias = re.search(
            rf'typedef\s+struct\s+([A-Za-z_]\w*)\s+{re.escape(type_name)}\s*;',
            text,
        )
        if alias:
            tag = alias.group(1)
            break
    bodies: list[str] = []
    named = (
        rf'typedef\s+struct\s+{re.escape(tag)}\s*\{{',
        rf'struct\s+{re.escape(tag)}\s*\{{',
    )
    anonymous = rf'typedef\s+struct\s*\{{'
    for raw in texts:
        text = _strip_c_comments(raw)
        for pattern in named:
            for match in re.finditer(pattern, text):
                end = _match_code_brace(text, match.end() - 1)
                if end > match.end():
                    bodies.append(text[match.end():end])
        if tag == type_name:
            for match in re.finditer(anonymous, text):
                end = _match_code_brace(text, match.end() - 1)
                if end <= match.end():
                    continue
                if re.match(rf'\s*{re.escape(type_name)}\b', text[end + 1:]):
                    bodies.append(text[match.end():end])
    field_pattern = re.compile(
        rf'([A-Za-z_][\w\s\*]*)\b{re.escape(field)}\b'
    )
    for body in bodies:
        for fragment in body.split(';'):
            match = field_pattern.search(fragment)
            if not match:
                continue
            shown = ' '.join(match.group(1).split())
            if shown:
                return shown
    return None


def _type_texts(path: Path, case_ir: dict[str, Any] | None) -> list[str]:
    texts: list[str] = []
    files = [path]
    if path.parent.is_dir():
        files.extend(sorted(path.parent.glob('*.h')))
    root = _source_root(case_ir)
    includes = (((case_ir or {}).get('app_profile') or {}).get('symbolic_slice') or {}).get('include_dirs') or []
    for item in includes:
        base = Path(str(item))
        if base.is_dir():
            files.extend(sorted(base.glob('*.h')))
    if root is not None:
        include = root / 'include'
        if include.is_dir():
            files.extend(sorted(include.glob('*.h')))
    seen: set[str] = set()
    for item in files:
        key = str(item.resolve()) if item.exists() else str(item)
        if key in seen or not item.is_file():
            continue
        seen.add(key)
        try:
            texts.append(item.read_text(encoding='utf-8', errors='replace'))
        except OSError:
            continue
    return texts


def _local_pointer_type(body: str, name: str) -> str | None:
    found = re.findall(
        rf'(?:const\s+)?(?:(struct|union|enum)\s+)?([A-Za-z_]\w*)\s*\*\s*{re.escape(name)}\b',
        body,
    )
    if len(found) != 1:
        return None
    kind_word, type_name = found[0]
    return f'{kind_word} {type_name}' if kind_word else type_name


def _paired_pointer_field(text: str, function: str, field: str) -> tuple[str, str, str] | None:
    for _name, body, _static in _defined_functions(text):
        stores = re.findall(
            rf'(?<![\w])([A-Za-z_]\w*)\s*(?:\.|->)\s*{re.escape(field)}\s*=\s*{re.escape(function)}\s*;',
            body,
        )
        if len(stores) != 1:
            continue
        base = stores[0]
        paired = re.findall(
            rf'(?<![\w]){re.escape(base)}\s*(?:\.|->)\s*([A-Za-z_]\w*)\s*=\s*\(\s*([A-Za-z_]\w*)\s*\)\s*([A-Za-z_]\w*)\s*;',
            body,
        )
        if len(paired) != 1:
            return None
        other, cast, local = paired[0]
        if other == field:
            return None
        kind = _local_pointer_type(body, local)
        if kind is None:
            return None
        return other, cast, kind
    return None


def _local_record_text(source: str, type_name: str) -> str | None:
    text = _strip_c_comments(source)
    shown = ' '.join(type_name.split())
    words = shown.split()
    if words and words[0] in {'struct', 'union', 'enum'} and len(words) == 2:
        match = re.search(rf'{words[0]}\s+{re.escape(words[1])}\s*\{{', text)
        if not match:
            return None
        end = _match_code_brace(text, match.end() - 1)
        if end < match.end():
            return None
        body = ' '.join(text[match.start():end + 1].split())
        if not text[end + 1:end + 8].lstrip().startswith(';'):
            body += ';'
        else:
            body += ';'
        return body
    for match in re.finditer(r'typedef\s+struct(?:\s+[A-Za-z_]\w*)?\s*\{', text):
        end = _match_code_brace(text, match.end() - 1)
        if end < match.end():
            continue
        tail = re.match(rf'\s*{re.escape(shown)}\s*;', text[end + 1:])
        if not tail:
            continue
        return ' '.join(text[match.start():end + 1 + tail.end()].split())
    return None


def _single_object_pointer(shown: str | None) -> str | None:
    if not shown or '(' in shown or shown.count('*') != 1:
        return None
    pointee = ' '.join(shown.rsplit('*', 1)[0].split())
    if not pointee:
        return None
    return pointee


def _type_word(shown: str) -> str:
    words = [
        word for word in shown.replace('*', ' ').split()
        if word not in {'const', 'volatile', 'struct', 'union', 'enum'}
    ]
    return words[-1] if words else ''


def _guard_entry_objects(source: str,
                         function: str,
                         texts: list[str],
                         call_arg: str,
                         paired_type: str) -> tuple[list[str], list[str]]:
    signature = parse_c_function_signature(source, function, include_static=True)
    body = None
    for name, item, _static in _defined_functions(source):
        if name == function:
            body = item
            break
    if signature is None or body is None or not call_arg:
        return [], []
    bases: dict[str, tuple[str, str]] = {}
    for item in signature['parameters']:
        if item.get('kind') != 'pointer':
            continue
        bases[str(item.get('name') or '')] = (f'{call_arg}_obj', _type_word(str(item.get('decl_type') or item.get('type_text') or '')))
        break
    paired_shown = ' '.join(paired_type.split())
    if paired_shown:
        cast = re.compile(
            r'(?:const\s+)?((?:struct|union|enum)\s+[A-Za-z_]\w*|[A-Za-z_]\w*)\s*\*\s*([A-Za-z_]\w*)\s*=\s*\(\s*\1\s*\*\s*\)\s*([A-Za-z_]\w*)\s*;'
        )
        params = {str(item.get('name') or ''): item for item in signature['parameters']}
        for match in cast.finditer(body):
            type_text, local, src = match.group(1), match.group(2), match.group(3)
            if ' '.join(type_text.split()) != paired_shown:
                continue
            origin = params.get(src)
            if origin is None or origin.get('kind') == 'pointer':
                continue
            bases[local] = ('paired_slot', _type_word(type_text))
    decls: list[str] = []
    statements: list[str] = []
    records: list[str] = []
    seen_records: set[str] = set()
    slots: dict[tuple[str, str], str] = {}
    used_names: set[str] = set()

    def add_object(driver: str, field: str, pointee: str) -> str | None:
        key = (driver, field)
        if key in slots:
            return slots[key]
        if len(slots) >= 8:
            return None
        slot = f'vg_{field}_obj'
        if slot in used_names:
            slot = f'vg_{field}_{len(slots)}_obj'
        used_names.add(slot)
        slots[key] = slot
        record = _local_record_text(source, pointee)
        if record and record not in seen_records:
            seen_records.add(record)
            records.append(record)
        decls.append(f'    {pointee} {slot};')
        decls.append(f'    memset(&{slot}, 0, sizeof({slot}));')
        statements.append(f'    {driver}.{field} = &{slot};')
        return slot

    for src, (driver, type_word) in list(bases.items()):
        if not type_word:
            continue
        chains = re.findall(
            rf'(?<![\w]){re.escape(src)}\s*->\s*([A-Za-z_]\w*)(?:\s*->\s*([A-Za-z_]\w*))?',
            body,
        )
        for field, nested in chains:
            shown = _struct_field_type(texts, type_word, field)
            pointee = _single_object_pointer(shown)
            if pointee is None:
                continue
            slot = add_object(driver, field, pointee)
            if slot is None or not nested:
                continue
            nested_type = _struct_field_type(texts, _type_word(pointee), nested)
            nested_pointee = _single_object_pointer(nested_type)
            if nested_pointee is not None:
                add_object(slot, nested, nested_pointee)
    for local, base, field in re.findall(
        r'(?<![\w])([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*;',
        body,
    ):
        slot = slots.get((bases.get(base, ('', ''))[0], field))
        if not slot:
            continue
        flag = re.search(rf'if\s*\(\s*!{re.escape(local)}\s*->\s*([A-Za-z_]\w*)\s*\)', body)
        if flag:
            statements.append(f'    {slot}.{flag.group(1)} = 1;')
    return decls + statements, records


def _indexed_other_handler(signature: dict[str, Any], name: str) -> str:
    params = _declaration_params(signature)
    joined = ', '.join(params) if params else 'void'
    names = [
        str(item.get('name') or '')
        for item in signature['parameters']
        if item.get('kind') != 'void' and item.get('name')
    ]
    unused = ' '.join(f'(void){item};' for item in names)
    shown = str(signature.get('return_decl') or signature['return_type'])
    if str(signature.get('return_type') or '') == 'void':
        statement = unused or '(void)0;'
    else:
        statement = f'{unused} return 0;'.strip()
    return f'static {shown} {name}({joined}) {{ {statement} }}'


def _indexed_handler_seed(body: str,
                          signature: dict[str, Any],
                          field: str,
                          target: str,
                          texts: list[str],
                          paired: tuple[str, str, str] | None,
                          slots: int,
                          other_handler: str | None = None) -> list[str] | None:
    indexed = re.findall(
        rf'(?<![\w])([A-Za-z_]\w*)\s*\[\s*([A-Za-z_]\w*|\d+)\s*\]\s*\.\s*{re.escape(field)}\s*\(',
        body,
    )
    plain = re.findall(
        rf'(?<![\w])([A-Za-z_]\w*)\s*(?:->|\.)\s*{re.escape(field)}\s*\(',
        body,
    )
    if not indexed or plain or len({item[0] for item in indexed}) != 1 or len({item[1] for item in indexed}) != 1:
        return None
    array_name, index_name = indexed[0]
    integer_params = {
        str(item.get('name') or '')
        for item in signature['parameters']
        if item.get('kind') == 'integer'
    }
    if not index_name.isdigit() and index_name not in integer_params:
        return None
    writes = re.findall(rf'(?<![\w]){re.escape(array_name)}\s*=\s*([^;]+);', body)
    if len(writes) != 1:
        return None
    element = _local_pointer_type(body, array_name)
    if element is None:
        return None
    origin = _strip_c_cast(writes[0])
    match = re.fullmatch(
        r'(?:\(\s*([A-Za-z_]\w*)\s*\)\s*->|([A-Za-z_]\w*)\s*->)\s*((?:[A-Za-z_]\w*\.)*)elts',
        origin,
    )
    if not match:
        return None
    owner = match.group(1) or match.group(2)
    member_path = match.group(3)[:-1] if match.group(3).endswith('.') else match.group(3)
    owner_writes = re.findall(rf'(?<![\w]){re.escape(owner)}\s*=\s*([^;]+);', body)
    if len(owner_writes) != 1:
        return None
    owner_expr = _strip_c_cast(owner_writes[0])
    rooted = re.fullmatch(
        r'\(\s*([A-Za-z_]\w*)\s*\)\s*->\s*([A-Za-z_]\w*)\s*\[\s*([^\]]+?)\s*\]',
        owner_expr,
    )
    if not rooted:
        rooted = re.fullmatch(
            r'([A-Za-z_]\w*)\s*->\s*([A-Za-z_]\w*)\s*\[\s*([^\]]+?)\s*\]',
            owner_expr,
        )
    if not rooted or not _parameter_object(signature, rooted.group(1)):
        return None
    param, member, index_expr = rooted.group(1), rooted.group(2), rooted.group(3).strip()
    param_type = ''
    for item in signature['parameters']:
        if str(item.get('name') or '') == param:
            param_type = str(item.get('decl_type') or item.get('type_text') or '')
            break
    param_words = [word for word in param_type.replace('*', ' ').split() if word not in {'const', 'struct'}]
    if not param_words:
        return None
    member_type = _struct_field_type(texts, param_words[-1], member)
    if member_type is None or member_type.count('*') < 2:
        return None
    owner_type = _local_pointer_type(body, owner)
    if owner_type is None:
        return None
    uses = re.findall(
        rf'(?<![\w]){re.escape(param)}\s*->\s*([A-Za-z_]\w*)\s*\[\s*{re.escape(index_name)}\s*\]',
        body,
    )
    value_fields = [name for name in dict.fromkeys(uses) if name != member]
    value_types = {name: _struct_field_type(texts, param_words[-1], name) for name in value_fields}
    if any(shown is None or shown.count('*') != 1 for shown in value_types.values()):
        return None
    slot_count = slots
    if index_name.isdigit():
        slot_count = int(index_name) + 1
    owner_slot = f'{owner}_slot'
    array_slot = f'{array_name}_slots'
    pointer_slot = f'{member}_slots'
    pointer_type = member_type.rsplit('*', 1)[0].strip()
    decls = [
        f'    {owner_type} {owner_slot};',
        f'    {pointer_type} {pointer_slot}[1];',
        f'    {element} {array_slot}[{slot_count}];',
    ]
    if paired is not None:
        decls.append(f'    {paired[2]} paired_slot;')
    value_rows: list[tuple[str, str, str]] = []
    for name, shown in value_types.items():
        if shown is None:
            return None
        pointee = shown.rsplit('*', 1)[0].strip()
        rows = f'{name}_slots'
        decls.append(f'    {pointee} {rows}[{slot_count}];')
        value_rows.append((name, pointee, rows))
    lines = list(decls)
    lines.extend([
        f'    memset(&{owner_slot}, 0, sizeof({owner_slot}));',
        f'    memset({pointer_slot}, 0, sizeof({pointer_slot}));',
        f'    {pointer_slot}[0] = &{owner_slot};',
        f'    {param}_obj.{member} = {pointer_slot};',
        f'    __CPROVER_assume(({index_expr}) == 0);',
        f'    memset({array_slot}, 0, sizeof({array_slot}));',
    ])
    if paired is not None:
        lines.append('    memset(&paired_slot, 0, sizeof(paired_slot));')
    other_name = other_handler if other_handler and slot_count > 1 else ''
    for offset in range(slot_count):
        handler = target if offset == 0 or not other_name else other_name
        lines.append(f'    {array_slot}[{offset}].{field} = {handler};')
        if paired is not None:
            other, cast, _kind = paired
            if offset == 0 or not other_name:
                lines.append(f'    {array_slot}[{offset}].{other} = ({cast})&paired_slot;')
            else:
                lines.append(f'    {array_slot}[{offset}].{other} = 0;')
    chain = '.'.join(part for part in member_path.split('.') if part)
    prefix = f'{owner_slot}.{chain}' if chain else owner_slot
    lines.append(f'    {prefix}.elts = {array_slot};')
    if re.search(rf'(?<![\w]){re.escape(chain)}\.nelts\b' if chain else r'(?<![\w])nelts\b', body):
        lines.append(f'    {prefix}.nelts = {slot_count};')
    for name, _pointee, rows in value_rows:
        lines.extend([
            f'    memset({rows}, 0, sizeof({rows}));',
            f'    {param}_obj.{name} = {rows};',
        ])
    return lines


def _handler_field_plan(path: Path,
                        text: str,
                        function: str,
                        case_ir: dict[str, Any] | None) -> dict[str, Any] | None:
    found = _unique_field_caller(path, text, function, case_ir)
    if found is not None:
        caller, caller_path, field = found
        try:
            caller_text = caller_path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            return None
        expanded = _expand_definition_macros(caller_path, caller_text)
        signature = parse_c_function_signature(expanded, caller, include_static=True)
        if signature is None:
            return None
        body = None
        for name, item_body, _static in _defined_functions(expanded):
            if name == caller:
                body = item_body
                break
        if body is None:
            return None
        body = _apply_subst_macros(body, _subst_macros(caller_path))
        seeded = _handler_seed(body, signature, field, '__VG_TARGET__', _type_texts(caller_path, case_ir))
        if seeded is not None:
            setup, reassign = seeded
            return {
                'caller': caller,
                'path': caller_path,
                'field': field,
                'setup': setup,
                'reassign': reassign,
            }
    fields = _stored_fields(text, function)
    if len(fields) != 1:
        return None
    field = fields[0]
    root = _source_root(case_ir)
    files = sorted(path.parent.glob('*.c')) if path.parent.is_dir() else []
    callers = _callers_of_field(field, function, files, limit=8)
    if root is not None and root.is_dir():
        distant = [
            item for item in root.rglob('*.c')
            if item.is_file() and item.parent != path.parent
        ]
        callers.extend(_callers_of_field(field, function, distant, limit=8))
    elif root is None:
        distant = [
            item for item in _slice_c_files(case_ir)
            if item.is_file() and item.parent != path.parent
        ]
        callers.extend(_callers_of_field(field, function, distant, limit=8))
    deduped: list[tuple[str, Path]] = []
    seen_callers: set[str] = set()
    for caller, caller_path in callers:
        if caller in seen_callers:
            continue
        seen_callers.add(caller)
        deduped.append((caller, caller_path))
    if not deduped or len(deduped) > 8:
        return None
    guard_sig = parse_c_function_signature(_expand_definition_macros(path, text), function, include_static=True)
    guard_param = ''
    if guard_sig and guard_sig['parameters']:
        guard_param = ' '.join(str(guard_sig['parameters'][0].get('decl_type') or guard_sig['parameters'][0].get('type_text') or '').split())
    paired = _paired_pointer_field(text, function, field)
    chosen: tuple[str, Path, list[str]] | None = None
    for caller, caller_path in deduped:
        try:
            caller_text = caller_path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        expanded = _expand_definition_macros(caller_path, caller_text)
        signature = parse_c_function_signature(expanded, caller, include_static=True)
        if signature is None:
            continue
        body = None
        for name, item_body, _static in _defined_functions(expanded):
            if name == caller:
                body = _apply_subst_macros(item_body, _subst_macros(caller_path))
                break
        if body is None:
            continue
        call_arg = re.search(
            rf'{re.escape(field)}\s*\(\s*([A-Za-z_]\w*)',
            body,
        )
        if guard_param and call_arg:
            arg_type = ''
            for item in signature['parameters']:
                if str(item.get('name') or '') == call_arg.group(1):
                    arg_type = ' '.join(str(item.get('decl_type') or item.get('type_text') or '').split())
                    break
            if arg_type != guard_param:
                continue
        seeded = _indexed_handler_seed(
            body, signature, field, '__VG_TARGET__', _type_texts(caller_path, case_ir), paired, 17,
            '__vg_indexed_other' if guard_sig is not None else None,
        )
        if seeded is None:
            continue
        if chosen is not None:
            return None
        chosen = (caller, caller_path, seeded, call_arg.group(1) if call_arg else '')
    if chosen is None:
        return None
    caller, caller_path, seeded, call_arg_name = chosen
    reassign = '\n'.join(line for line in seeded if '__VG_TARGET__' in line)
    extra, extra_records = _guard_entry_objects(
        text, function, _type_texts(path, case_ir), call_arg_name, paired[2] if paired is not None else '',
    )
    seeded = [*seeded, *extra]
    parts: list[str] = []
    for record in extra_records:
        if record not in parts:
            parts.append(record)
    if paired is not None:
        record = _local_record_text(text, paired[2])
        if record and record not in parts:
            parts.append(record)
    if any('__vg_indexed_other' in line for line in seeded) and guard_sig is not None:
        parts.append(_indexed_other_handler(guard_sig, '__vg_indexed_other'))
    prelude = '\n'.join(parts)
    return {
        'caller': caller,
        'path': caller_path,
        'field': field,
        'setup': seeded,
        'reassign': reassign,
        'prelude': prelude or '',
    }


def _slice_has_file(sym_scope: dict[str, Any], path: Path) -> bool:
    if not path.exists():
        return False
    resolved = str(path.resolve())
    for raw in sym_scope.get('slice_sources') or []:
        item = Path(str(raw))
        if item.exists() and str(item.resolve()) == resolved:
            return True
    return False


def _seed_covering_field_caller(sym_scope: dict[str, Any],
                               entry: str,
                               case_ir: dict[str, Any] | None) -> None:
    if sym_scope.get('handler_seeds') or not entry:
        return
    for guard in (case_ir or {}).get('guards') or []:
        name = str(guard.get('function') or '')
        if not name or name == entry:
            continue
        path = _definition_path(sym_scope, name, case_ir)
        if path is None or not path.is_file():
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        plan = _handler_field_plan(path, text, name, case_ir)
        if plan is None or str(plan.get('caller') or '') != entry:
            continue
        if not _slice_has_file(sym_scope, plan['path']):
            continue
        if _handler_field_entry(sym_scope, name, path, text, case_ir) == entry:
            return
        sym_scope.pop('handler_seeds', None)
        sym_scope.pop('handler_decls', None)


def _handler_field_entry(sym_scope: dict[str, Any],
                         function: str,
                         path: Path,
                         text: str,
                         case_ir: dict[str, Any] | None) -> str | None:
    plan = _handler_field_plan(path, text, function, case_ir)
    if plan is None or not _slice_has_file(sym_scope, plan['path']):
        return None
    target = _call_target(sym_scope, function)
    if target is None:
        return None
    decls = []
    prelude = str(plan.get('prelude') or '').strip()
    if prelude:
        decls.append(prelude)
    decls.append(_handler_decl(target[0], target[1]))
    groups = [[line.replace('__VG_TARGET__', target[0]) for line in plan['setup']]]
    for guard in (case_ir or {}).get('guards') or []:
        other = str(guard.get('function') or '')
        if not other or other == function:
            continue
        other_path = _definition_path(sym_scope, other, case_ir)
        if other_path is None or not other_path.is_file():
            continue
        try:
            other_text = other_path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        if plan['field'] not in _stored_fields(other_text, other):
            continue
        other_target = _call_target(sym_scope, other)
        if other_target is None:
            continue
        decls.append(_handler_decl(other_target[0], other_target[1]))
        groups.append([plan['reassign'].replace('__VG_TARGET__', other_target[0])])
    sym_scope['handler_decls'] = decls
    sym_scope['handler_seeds'] = groups
    return str(plan['caller'])


def _handler_decl(name: str, signature: dict[str, Any]) -> str:
    params = ', '.join(_declaration_params(signature)) or 'void'
    shown = str(signature.get('return_decl') or signature['return_type'])
    return f'{shown} {name}({params});'


def _apply_registration(sym_scope: dict[str, Any],
                        function: str,
                        case_ir: dict[str, Any] | None) -> str | None:
    path = _definition_path(sym_scope, function, case_ir)
    if path is None:
        return None
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None
    slot = _slot_entry(sym_scope, function, path, text, case_ir)
    if slot:
        return slot
    field = _field_entry(sym_scope, function, path, text, case_ir)
    if field:
        return field
    handler = _handler_field_entry(sym_scope, function, path, text, case_ir)
    if handler:
        return handler
    corpus = _registration_corpus(path, case_ir)
    hooked = _hook_entry(sym_scope, function, text, corpus)
    if hooked:
        return hooked
    return _filter_entry(sym_scope, function, text, corpus)


def registration_caller_files(case_ir: dict[str, Any], names: list[str]) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()
    scope = {'slice_sources': list((case_ir.get('symbolization_scope') or {}).get('slice_sources') or [])}
    for name in names:
        path = _definition_path(scope, str(name), case_ir)
        if path is None or not path.is_file():
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        caller = _unique_slot_caller(path, text, str(name), case_ir)
        caller_path = caller[1] if caller is not None else None
        rejected = _field_multi_rejected(case_ir, str(name), scope)
        if caller_path is None and not rejected:
            plan = _handler_field_plan(path, text, str(name), case_ir)
            if plan is not None:
                caller_path = plan['path']
        if caller_path is not None and caller_path.is_file() and not (rejected and caller is None):
            resolved = caller_path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                found.append(resolved)
        for extra in _field_seed_plans(case_ir, str(name), scope):
            extra_path = Path(str(extra.get('path') or ''))
            if not extra_path.is_file():
                continue
            resolved = extra_path.resolve()
            if resolved not in seen:
                seen.add(resolved)
                found.append(resolved)
    return found


_SOURCE_CALLER_CACHE: dict[tuple[str, str], list[dict[str, str]]] = {}


def _listed_field_callers(case_ir: dict[str, Any] | None,
                          function: str,
                          sym_scope: dict[str, Any] | None = None) -> list[tuple[str, Path]]:
    if sym_scope is not None:
        scope = sym_scope
    elif _source_root(case_ir) is None:
        scope = {'slice_sources': [str(item) for item in _slice_c_files(case_ir)]}
    else:
        scope = {'slice_sources': []}
    defined = _definition_path(scope, function, case_ir)
    if defined is None or not defined.is_file() or not function:
        return []
    try:
        text = defined.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []
    fields = _stored_fields(text, function)
    if len(fields) != 1:
        return []
    field = fields[0]
    root = _source_root(case_ir)
    files = sorted(defined.parent.glob('*.c')) if defined.parent.is_dir() else []
    callers = _callers_of_field(field, function, files, limit=9)
    if root is not None and root.is_dir():
        distant = [
            item for item in root.rglob('*.c')
            if item.is_file() and item.parent != defined.parent
        ]
        callers.extend(_callers_of_field(field, function, distant, limit=9))
    else:
        distant = [
            item for item in _slice_c_files(case_ir, sym_scope)
            if item.is_file() and item.resolve() != defined.resolve() and item.parent != defined.parent
        ]
        callers.extend(_callers_of_field(field, function, distant, limit=9))
    deduped: list[tuple[str, Path]] = []
    seen: set[str] = set()
    for caller, caller_path in callers:
        if caller in seen:
            continue
        seen.add(caller)
        deduped.append((caller, caller_path))
    return deduped


def _field_seed_plans(case_ir: dict[str, Any] | None,
                      function: str,
                      sym_scope: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    deduped = _listed_field_callers(case_ir, function, sym_scope)
    if len(deduped) < 2 or len(deduped) > 8:
        return []
    if sym_scope is not None:
        defined_scope = sym_scope
    elif _source_root(case_ir) is None:
        defined_scope = {'slice_sources': [str(item) for item in _slice_c_files(case_ir)]}
    else:
        defined_scope = {'slice_sources': []}
    defined = _definition_path(defined_scope, function, case_ir)
    if defined is None:
        return []
    try:
        text = defined.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return []
    fields = _stored_fields(text, function)
    if len(fields) != 1:
        return []
    field = fields[0]
    plans: list[dict[str, Any]] = []
    for caller, caller_path in deduped:
        try:
            caller_text = caller_path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            return []
        expanded = _expand_definition_macros(caller_path, caller_text)
        signature = parse_c_function_signature(expanded, caller, include_static=True)
        if signature is None:
            return []
        body = None
        for name, item_body, _static in _defined_functions(expanded):
            if name == caller:
                body = item_body
                break
        if body is None:
            return []
        body = _apply_subst_macros(body, _subst_macros(caller_path))
        seeded = _handler_seed(body, signature, field, '__VG_TARGET__', _type_texts(caller_path, case_ir))
        if seeded is None:
            return []
        setup, reassign = seeded
        plans.append({
            'caller': caller,
            'path': caller_path,
            'field': field,
            'setup': setup,
            'reassign': reassign,
            'linkage': str(signature.get('linkage') or ''),
        })
    plans.sort(key=lambda item: str(item['caller']))
    return plans


def _field_multi_rejected(case_ir: dict[str, Any] | None,
                          function: str,
                          sym_scope: dict[str, Any] | None = None) -> bool:
    listed = _listed_field_callers(case_ir, function, sym_scope)
    if len(listed) < 2:
        return False
    return len(_field_seed_plans(case_ir, function, sym_scope)) < 2


def _prefixed_field_seed(plan: dict[str, Any] | None, signature: dict[str, Any]) -> list[str]:
    if not plan:
        return []
    caller = str(signature.get('name') or '')
    params = [str(item.get('name') or '') for item in signature.get('parameters') or [] if item.get('name')]
    rows: list[str] = []
    for line in plan.get('setup') or []:
        text = str(line)
        for name in params:
            text = re.sub(rf'(?<![\w]){re.escape(name)}_obj\b', f'{caller}_{name}_obj', text)
        text = re.sub(
            r'(?<![\w])([A-Za-z_]\w*_slot)\b',
            lambda match, prefix=caller: f'{prefix}_{match.group(1)}',
            text,
        )
        rows.append(text)
    return rows


def source_direct_callers(case_ir: dict[str, Any] | None, function: str) -> list[dict[str, str]]:
    root = _source_root(case_ir)
    admitted = [] if root is not None else _slice_c_files(case_ir)
    if not function or (root is None and not admitted):
        return []
    if root is not None:
        key = (str(root.resolve()), function)
        paths = sorted(item for item in root.rglob('*.c') if item.is_file())
    else:
        key = ('slice', tuple(str(item.resolve()) for item in admitted), function)
        paths = admitted
    cached = _SOURCE_CALLER_CACHE.get(key)
    if cached is not None:
        return [dict(item) for item in cached]
    found: list[dict[str, str]] = []
    seen_names: set[str] = set()
    for path in paths:
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        if function not in text:
            continue
        expanded = _expand_definition_macros(path, text)
        signatures: dict[str, dict[str, Any] | None] = {}
        for name, body, _static in _defined_functions(expanded):
            if name == function or name in seen_names:
                continue
            if not _body_calls(body, function):
                continue
            if name not in signatures:
                signatures[name] = parse_c_function_signature(expanded, name, include_static=True)
            signature = signatures[name]
            if signature is None:
                continue
            seen_names.add(name)
            found.append({
                'function': name,
                'file': str(path.resolve()),
                'linkage': str(signature.get('linkage') or ''),
            })
    defined = _definition_path(
        {'slice_sources': [str(item) for item in admitted]},
        function,
        case_ir,
    )
    if defined is not None and defined.is_file():
        try:
            defined_text = defined.read_text(encoding='utf-8', errors='replace')
        except OSError:
            defined_text = ''
        field_plan = _handler_field_plan(defined, defined_text, function, case_ir)
        caller_name = str((field_plan or {}).get('caller') or '')
        if field_plan is not None and caller_name and caller_name not in seen_names:
            caller_path = Path(str(field_plan['path']))
            try:
                caller_text = caller_path.read_text(encoding='utf-8', errors='replace')
            except OSError:
                caller_text = ''
            signature = parse_c_function_signature(
                _expand_definition_macros(caller_path, caller_text),
                caller_name,
                include_static=True,
            )
            if signature is not None:
                seen_names.add(caller_name)
                found.append({
                    'function': caller_name,
                    'file': str(caller_path.resolve()) if caller_path.exists() else str(caller_path),
                    'linkage': str(signature.get('linkage') or ''),
                    'via': 'field',
                })
        for plan in _field_seed_plans(case_ir, function):
            extra_name = str(plan.get('caller') or '')
            if not extra_name or extra_name in seen_names:
                continue
            extra_path = Path(str(plan['path']))
            seen_names.add(extra_name)
            found.append({
                'function': extra_name,
                'file': str(extra_path.resolve()) if extra_path.exists() else str(extra_path),
                'linkage': str(plan.get('linkage') or ''),
                'via': 'field',
            })
    found.sort(key=lambda item: (item['function'], item['file']))
    _SOURCE_CALLER_CACHE[key] = found
    return [dict(item) for item in found]


def _seed_tokens(case_ir: dict[str, Any] | None) -> set[str]:
    seeds = ((case_ir or {}).get('seed_traces') or {})
    rows: list[Any] = []
    benign = seeds.get('benign_seeds') or []
    if isinstance(benign, list):
        rows.extend(benign)
    repro = seeds.get('poc_reproducer')
    if isinstance(repro, dict):
        rows.append(repro)
    elif isinstance(repro, list):
        rows.extend(repro)
    tokens: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        for key in ('group', 'id', 'path'):
            for part in re.split(r'[^A-Za-z0-9]+', str(row.get(key) or '')):
                if len(part) >= 3:
                    tokens.add(part.lower())
    return tokens


def _unique_seed_caller(case_ir: dict[str, Any] | None, names: list[str]) -> str | None:
    tokens = _seed_tokens(case_ir)
    if not tokens:
        return None
    scored: list[tuple[int, str]] = []
    for name in names:
        overlap = {part.lower() for part in name.split('_') if len(part) >= 3} & tokens
        if len(overlap) >= 2:
            scored.append((len(overlap), name))
    if not scored:
        return None
    best = max(item[0] for item in scored)
    tops = [name for score, name in scored if score == best]
    if len(tops) != 1:
        return None
    return tops[0]


def seed_activated_files(case_ir: dict[str, Any], names: list[str]) -> list[Path]:
    found: list[Path] = []
    seen: set[Path] = set()
    for name in names:
        record = _seed_source_lift(case_ir, str(name))
        if record is None:
            continue
        path = Path(record['file'])
        if not path.is_file():
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        found.append(path)
    return found


def _file_function_body(path: str, name: str) -> str | None:
    try:
        text = Path(path).read_text(encoding='utf-8', errors='replace')
    except OSError:
        return None
    for found, body, _static in _defined_functions(text):
        if found == name:
            return body
    return None


def _seed_source_lift(case_ir: dict[str, Any] | None, start: str) -> dict[str, str] | None:
    if _source_root(case_ir) is None or not start:
        return None
    current = start
    current_file = ''
    held = False
    hops = 0
    extra = 0
    live: dict[str, int] = {}
    summaries: dict[str, tuple[set[str], set[str]]] = {}
    while True:
        callers = source_direct_callers(case_ir, current)
        if not callers:
            break
        if len(callers) == 1:
            nxt = callers[0]
            callee_text = ''
            if current_file:
                try:
                    callee_text = Path(current_file).read_text(encoding='utf-8', errors='replace')
                except OSError:
                    callee_text = ''
            owner_text = ''
            try:
                owner_text = Path(nxt['file']).read_text(encoding='utf-8', errors='replace')
            except OSError:
                owner_text = ''
            kind = _lift_step_body(
                _file_function_body(nxt['file'], nxt['function']),
                current,
                live,
                _parameter_names(None, current, callee_text),
                nxt['function'],
                _parameter_names(None, nxt['function'], owner_text),
                summaries,
            )
            action, held, hops, extra = _note_lift(kind, held, hops, extra, 4)
            current = nxt['function']
            current_file = nxt['file']
            if action != 'continue':
                return dict(nxt)
            continue
        seeded = _unique_seed_caller(case_ir, [item['function'] for item in callers])
        if seeded:
            for item in callers:
                if item['function'] == seeded:
                    return item
        break
    if current != start and current_file:
        return {'function': current, 'file': current_file}
    return None


def choose_call_entries(sym_scope: dict[str, Any],
                        guard: str,
                        case_ir: dict[str, Any] | None = None,
                        limit: int = 4) -> list[str] | None:
    current = guard
    hops = 0
    held = False
    extra = 0
    live: dict[str, int] = {}
    summaries: dict[str, tuple[set[str], set[str]]] = {}
    while True:
        names, static_group = _multi_direct(sym_scope, current)
        if not names:
            registered = _apply_registration(sym_scope, current, case_ir)
            if registered:
                return [registered]
            lifted = _seed_source_lift(case_ir, current)
            if lifted and _caller_step_ok(
                sym_scope,
                lifted['function'],
                lifted.get('linkage') == 'static',
            ):
                return [lifted['function']]
            plans = _field_seed_plans(case_ir, current, sym_scope)
            target = _call_target(sym_scope, current) if len(plans) >= 2 else None
            if target is not None:
                rewritten = []
                for plan in plans:
                    item = dict(plan)
                    item['setup'] = [
                        str(line).replace('__VG_TARGET__', target[0]) for line in plan['setup']
                    ]
                    rewritten.append(item)
                sym_scope['field_caller_plans'] = rewritten
                sym_scope['field_caller_decl'] = _handler_decl(target[0], target[1])
                return [str(item['caller']) for item in rewritten]
            return [current]
        if len(names) >= 2:
            seeded = _unique_seed_caller(case_ir, names)
            if seeded and _caller_step_ok(sym_scope, seeded, static_group):
                return [seeded]
        if len(names) >= 2 and not static_group:
            dispatchers = _indirect_dispatchers(sym_scope, names)
            if dispatchers and all(_entry_parses(sym_scope, name, True) for name in dispatchers):
                activated = _trace_names(case_ir or {})
                ordered = [name for name in dispatchers if name in activated]
                ordered.extend(name for name in dispatchers if name not in activated)
                return ordered
        if len(names) == 1:
            if not _caller_step_ok(sym_scope, names[0], static_group):
                return [current]
            kind = _lift_step(sym_scope, names[0], current, live, summaries)
            action, held, hops, extra = _note_lift(kind, held, hops, extra, limit)
            current = names[0]
            if action == 'continue':
                continue
            return [current]
        entries = _expand_caller_group(
            sym_scope, names, static_group, case_ir, max(limit - hops - 1, 0), current,
        )
        if entries is None:
            if current == guard:
                return None
            return [current]
        return entries
    return [current]


def _bare_code_slot(sym_scope: dict[str, Any], function: str, param: str) -> dict[str, Any] | None:
    for slot in (sym_scope.get('code_word_slots') or {}).get(function) or []:
        if slot.get('param') == param and not slot.get('field'):
            return slot
    return None


def _code_word_lines(array: str, opcode: str | None) -> list[str]:
    rows = [
        f'    uintptr_t {array}[8];',
        f'    memset({array}, 0, sizeof({array}));',
    ]
    if opcode:
        rows.append(f'    {array}[0] = (uintptr_t){opcode};')
    return rows


def _field_code_lines(sym_scope: dict[str, Any], function: str, param: str, local: str) -> list[str]:
    rows: list[str] = []
    for slot in (sym_scope.get('code_word_slots') or {}).get(function) or []:
        field = slot.get('field')
        if slot.get('param') != param or not field:
            continue
        array = f'{local}_{field}_words'
        rows.extend(_code_word_lines(array, slot.get('opcode')))
        rows.append(f'    {local}.{field} = (void *){array};')
    return rows


def _caller_call_text(signature: dict[str, Any],
                      index: int,
                      sym_scope: dict[str, Any] | None = None) -> tuple[list[str], str, list[tuple[str, str]]]:
    symbol_name = str(signature['name'])
    function = str(signature.get('call_name') or symbol_name)
    return_type = str(signature['return_type'])
    locals: list[str] = []
    arguments: list[str] = []
    integers: list[tuple[str, str]] = []
    brigade_names: list[str] = []
    function_stubs: list[str] = []
    for item in signature['parameters']:
        name = str(item['name'])
        symbol = f'__vg_in_{symbol_name}_{name}'
        if item['kind'] == 'integer':
            integers.append((symbol, name))
            arguments.append(f'(({item["type_text"]}){symbol})')
            continue
        if item['kind'] == 'function_pointer':
            stub, local, argument = _function_pointer_binding(item, symbol_name)
            function_stubs.append(stub)
            locals.append(local)
            arguments.append(_address_callback(item, name, argument, locals))
            continue
        local = f'{symbol_name}_{name}_obj'
        if item.get('value_array_dims'):
            shown = ''.join(f'[{int(size)}]' for size in item['value_array_dims'])
            locals.append(f'    {item["pointee"]} {local}{shown};')
            locals.append(f'    memset({local}, 0, sizeof({local}));')
            arguments.append(local)
            continue
        if item.get('array_dims'):
            stored, argument = _array_pointer_storage(item, local)
            locals.extend(stored)
            arguments.append(argument)
            continue
        if item['kind'] == 'buffer' and item.get('array_len'):
            locals.append(f'    {item["pointee"]} {local}[{int(item["array_len"])}];')
            locals.append(f'    memset({local}, 0, sizeof({local}));')
            arguments.append(local)
            continue
        if item['kind'] == 'buffer' and str(item.get('decl_type') or '').count('*') > 1:
            stored, argument = _pointer_storage(item, local)
            locals.extend(stored)
            arguments.append(argument)
            continue
        if item['kind'] == 'buffer':
            bare = _bare_code_slot(sym_scope or {}, symbol_name, name)
            if bare is not None:
                locals.extend(_code_word_lines(local, bare.get('opcode')))
            else:
                locals.append(f'    uint8_t {local}[16];')
                locals.append(f'    memset({local}, 0, sizeof({local}));')
            arguments.append(local)
            continue
        if item['kind'] == 'struct_value':
            locals.append(f'    {item["type_text"]} {local};')
            locals.append(f'    memset(&{local}, 0, sizeof({local}));')
            locals.extend(_field_code_lines(sym_scope or {}, symbol_name, name, local))
            arguments.append(local)
            continue
        if _is_brigade_pointer(item):
            setup, argument = _brigade_setup(f'{symbol_name}_{name}')
            locals.extend(setup)
            arguments.append(argument)
            brigade_names.append(argument)
            continue
        stored, argument = _pointer_storage(item, local)
        locals.extend(stored)
        locals.extend(_field_code_lines(sym_scope or {}, symbol_name, name, local))
        arguments.append(argument)
    call_args = ', '.join(arguments)
    call = _result_lines(
        return_type,
        f'{function}({call_args})',
        f'obs->caller_status[{index}]',
        bool(signature.get('returns_aggregate')),
        f'vg_ret_{index}',
        signature.get('return_array_dims'),
        str(signature.get('return_stars') or ''),
        str(signature.get('return_pointee') or ''),
        str(signature.get('return_callback_args') or ''),
    )
    return locals, call + _brigade_checks(brigade_names), integers, function_stubs


def render_multi_caller_driver(family: str,
                               signatures: list[dict[str, Any]],
                               sym_scope: dict[str, Any]) -> str:
    _note_anonymous(sym_scope, signatures)
    bounds = sym_scope.get('input_bounds') or {}
    declarations, seed_sigs = _opcode_declarations(sym_scope, [str(item['name']) for item in signatures])
    declarations = list(declarations)
    locals: list[str] = []
    calls: list[str] = []
    symbols: list[tuple[str, str, str]] = []
    plans = {
        str(item.get('caller') or ''): item
        for item in (sym_scope.get('field_caller_plans') or [])
        if isinstance(item, dict)
    }
    decl = str(sym_scope.get('field_caller_decl') or '')
    if decl:
        declarations.append(decl)
    for index, signature in enumerate(signatures):
        parameters = list(signature['parameters'])
        decl_params = _declaration_params(signature)
        joined = ', '.join(decl_params) if decl_params else 'void'
        invoked = str(signature.get('call_name') or signature['name'])
        shown_return = str(signature.get('return_decl') or signature['return_type'])
        declarations.append(_function_declarator(signature, invoked, joined) + ';')
        call_locals, call, integers, function_stubs = _caller_call_text(signature, index, sym_scope)
        if function_stubs:
            declarations.append('extern _Bool __vulgate_missing_callee_hit;')
            declarations.extend(function_stubs)
        locals.extend(call_locals)
        calls.extend(_prefixed_field_seed(plans.get(str(signature['name'])), signature))
        calls.append(call)
        for symbol, param in integers:
            symbols.append((symbol, str(signature['name']), param))
    assumes = []
    for symbol, function, param in symbols:
        spec = bounds.get(f'{function}.{param}') or bounds.get(param) or {}
        low = int(spec.get('min', 0))
        high = int(spec.get('max', 16))
        assumes.append(f'    __CPROVER_assume({symbol} >= {low}ULL && {symbol} <= {high}ULL);')
    world_params = ', '.join(f'uint64_t {symbol}' for symbol, _function, _param in symbols)
    if world_params:
        world_params += ', '
    entry_params = f'{world_params}vg_proto_obs *obs'
    input_decls = '\n'.join(
        f'    uint64_t {symbol} = __vulgate_nondet_u64();' for symbol, _function, _param in symbols
    )
    input_args = ', '.join(symbol for symbol, _function, _param in symbols)
    if input_args:
        input_args += ', '
    needs_brigade = any(
        _is_brigade_pointer(item)
        for signature in signatures
        for item in signature['parameters']
    )
    model = HTTPD_ENV_MODEL + '\n' if needs_brigade else ''
    diff = '\n        || '.join(
        f'(obs0.caller_status[{index}] != obs1.caller_status[{index}])'
        for index in range(len(signatures))
    )
    return f'''{_family_preamble(family)}{model}#include <stdint.h>
#include <stddef.h>
#include <string.h>
{_merged_typedef_text([*signatures, *seed_sigs])}{chr(10).join(declarations)}

typedef struct vg_proto_obs {{
    uint64_t status_code;
    uint64_t caller_status[{len(signatures)}];
}} vg_proto_obs;

static void vg_proto_entry({entry_params}) {{
{chr(10).join(locals)}
{chr(10).join(calls)}
    obs->status_code = obs->caller_status[0];
}}

int __vg_run_world_0({entry_params}) {{
    vg_proto_entry({input_args}obs);
    return (int)obs->status_code;
}}
int __vg_run_world_1({entry_params}) {{
    vg_proto_entry({input_args}obs);
    return (int)obs->status_code;
}}

void __vg_verify_obligations(void) {{
{input_decls}
{chr(10).join(assumes)}
    vg_proto_obs obs0 = {{0}}, obs1 = {{0}};
    __vg_run_world_0({input_args}&obs0);
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    __vg_run_world_1({input_args}&obs1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}}

void __vg_impact_harness(void) {{
{input_decls}
{chr(10).join(assumes)}
    /*VG_IMPACT_REGION_ASSUME*/
    vg_proto_obs obs0 = {{0}}, obs1 = {{0}};
    __vg_run_world_0({input_args}&obs0);
    __vulgate_any_blocked = 0;
    __vg_run_world_1({input_args}&obs1);
    _Bool __vg_obs_diff = {diff};
    /*VG_IMPACT_QUERY_ASSERT*/
}}
'''


def _prototype_entry(sym_scope: dict[str, Any],
                     cut_fn: str,
                     guard_fn: str,
                     abstract_snapshot: dict[str, Any] | None) -> str:
    snap_cut = str((abstract_snapshot or {}).get('cut_function') or '')
    if snap_cut:
        return snap_cut
    scope_cut = str(sym_scope.get('cut_function') or '')
    if scope_cut:
        return scope_cut
    lifted = lift_unique_caller(sym_scope, guard_fn)
    if lifted:
        return lifted
    return cut_fn


def _declaration_params(signature: dict[str, Any]) -> list[str]:
    params = [_param_decl(item) for item in signature['parameters']]
    if signature.get('variadic'):
        params.append('...')
    return params


def render_static_export(signature: dict[str, Any]) -> str:
    original = str(signature['name'])
    export = str(signature.get('call_name') or original)
    params = _declaration_params(signature)
    joined = ', '.join(params) if params else 'void'
    arguments = ', '.join(str(item['name']) for item in signature['parameters'])
    if str(signature['return_type']) == 'void':
        statement = f'{original}({arguments});'
    else:
        statement = f'return {original}({arguments});'
    return _function_declarator(signature, export, joined) + f' {{ {statement} }}\n'


def _static_signature_in_sources(sym_scope: dict[str, Any], function: str) -> tuple[dict[str, Any] | None, Path | None]:
    for raw_path in sym_scope.get('slice_sources') or []:
        path = Path(str(raw_path))
        try:
            text = path.read_text(encoding='utf-8', errors='replace')
        except OSError:
            continue
        text = _expand_definition_macros(path, text)
        found = parse_c_function_signature(text, function, include_static=True)
        if found and found.get('linkage') == 'static':
            return _bind_aggregate_return(path, text, found), path
    return None, None


def _store_static_exports(sym_scope: dict[str, Any], exports: list[dict[str, str]]) -> None:
    if not exports:
        return
    stored = list(sym_scope.get('static_exports') or [])
    stored.extend(exports)
    sym_scope['static_exports'] = stored


def _bind_entry_signature(sym_scope: dict[str, Any],
                          name: str,
                          exports: list[dict[str, str]]) -> dict[str, Any] | None:
    found = _signature_for_cut(sym_scope, name)
    if found is not None:
        return found
    found, path = _static_signature_in_sources(sym_scope, name)
    if found is None or path is None:
        return None
    bound = dict(found)
    bound['call_name'] = f'__vg_export_{name}'
    exports.append({
        'function': name,
        'file': str(path.resolve()),
        'source': render_static_export(bound),
    })
    return bound


def _resolve_guard_signatures(case_ir: dict[str, Any],
                              sym_scope: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, str]]] | None:
    names: list[str] = []
    for guard in case_ir.get('guards') or []:
        name = str(guard.get('function') or '')
        if name and name not in names:
            names.append(name)
    if not names:
        return None
    signatures: list[dict[str, Any]] = []
    exports: list[dict[str, str]] = []
    for name in names:
        found = _signature_for_cut(sym_scope, name)
        if found is None:
            found, path = _static_signature_in_sources(sym_scope, name)
            if found is None or path is None:
                return None
            found = dict(found)
            found['call_name'] = f'__vg_export_{name}'
            exports.append({
                'function': name,
                'file': str(path.resolve()),
                'source': render_static_export(found),
            })
        signatures.append(found)
    return signatures, exports


_IMPLEMENTED_CUT_HARNESS_KINDS = frozenset({
    'brotli_stream_refill',
    'nginx_script_check_length',
    'nginx_script_regex_start',
    'nginx_alias_map_uri',
    'nginx_copy_filter_aio',
    'nginx_map_variable',
    'nginx_regex_captures',
    'nginx_h2_grpc_serializers',
    'nginx_dav_copy_move',
    'httpd_vhost_translate',
    'httpd_h2_c1_setup',
    'httpd_dav_proppatch',
    'httpd_session_proxy',
    'httpd_xml2enc_filter',
    'httpd_charset_out_filter',
    'httpd_proxy_html_comment',
    'httpd_rewrite_lookup',
    'php_multipart_startup',
    'php_session_progress',
})

_DOMAIN_HARNESS_BINDING_RE = re.compile(
    r'\b(obs1|res1|rc1|det1|ctx1|st1|elen1|fset1|bad_cap|startup_mp)\b'
)


def driver_prefers_kind_harness(oracle: dict[str, Any] | None,
                                sym_scope: dict[str, Any] | None) -> bool:
    scope = sym_scope or {}
    if scope.get('environment_source') == 'prototype':
        return False
    kind_name = str(scope.get('cut_harness_kind') or '')
    if kind_name not in _IMPLEMENTED_CUT_HARNESS_KINDS:
        return False
    if kind_name in {'nginx_script_check_length', 'nginx_script_regex_start'}:
        return True
    bindings = (oracle or {}).get('bindings') or {}
    if not isinstance(bindings, dict) or not bindings:
        return False
    joined = ' '.join(str(v) for v in bindings.values() if v is not None)
    return bool(_DOMAIN_HARNESS_BINDING_RE.search(joined))


def _generate_cut_driver_body(app_family: str,
                              case_ir: dict[str, Any],
                              cut_fn: str,
                              guard_fn: str,
                              oracle: dict[str, Any],
                              sym_scope: dict[str, Any],
                              abstract_snapshot: dict[str, Any] | None = None) -> str:
    if 'inline_driver_c' in sym_scope:
        return str(sym_scope['inline_driver_c'])

    kind_name = sym_scope.get('cut_harness_kind')
    prefer_kind_harness = driver_prefers_kind_harness(oracle, sym_scope)
    sym_scope['driver_entry'] = ''
    sym_scope.pop('handler_seeds', None)
    sym_scope.pop('handler_decls', None)
    sym_scope.pop('field_caller_plans', None)
    sym_scope.pop('field_caller_decl', None)
    snap_cut = str((abstract_snapshot or {}).get('cut_function') or '')
    scope_cut = str(sym_scope.get('cut_function') or '')
    multi_rejected = False
    chosen_entry: str | None = None
    if not snap_cut and not scope_cut:
        chosen = choose_call_entries(sym_scope, guard_fn, case_ir)
        if chosen is None:
            multi_rejected = True
        elif len(chosen) >= 2:
            signatures = []
            pending: list[dict[str, str]] = []
            for entry_name in chosen:
                found = _bind_entry_signature(sym_scope, entry_name, pending)
                if found is None:
                    signatures = []
                    pending = []
                    break
                signatures.append(found)
            if len(signatures) >= 2 and not prefer_kind_harness:
                _store_static_exports(sym_scope, pending)
                sym_scope['code_word_slots'] = _code_word_slots(sym_scope, guard_fn, chosen)
                sym_scope['driver_entry'] = ''
                return render_multi_caller_driver(app_family, signatures, sym_scope)
            multi_rejected = True
        else:
            chosen_entry = chosen[0]
    sym_scope.pop('code_word_slots', None)
    guard_visible = chosen_entry == guard_fn and (
        _signature_for_cut(sym_scope, guard_fn) is not None
        or _static_signature_in_sources(sym_scope, guard_fn)[0] is not None
    )
    if chosen_entry is not None and (chosen_entry != guard_fn or guard_visible):
        slots = _code_word_slots(sym_scope, guard_fn, [chosen_entry])
        if slots:
            sym_scope['code_word_slots'] = slots
        entry = chosen_entry
    else:
        entry = _prototype_entry(sym_scope, cut_fn, guard_fn, abstract_snapshot)
    sym_scope['driver_entry'] = entry
    _seed_covering_field_caller(sym_scope, entry, case_ir)
    signature = _signature_for_cut(sym_scope, entry)
    forced = sym_scope.get('environment_source') == 'prototype'
    if not prefer_kind_harness and signature and (forced or not (multi_rejected and kind_name is not None)):
        return render_prototype_driver(app_family, signature, sym_scope)
    own_static_cut = bool(scope_cut) and entry == scope_cut and entry != guard_fn
    if not prefer_kind_harness and not (multi_rejected and kind_name is not None) and (entry not in {guard_fn, cut_fn} or own_static_cut):
        pending = []
        bound = _bind_entry_signature(sym_scope, entry, pending)
        if bound is not None:
            _store_static_exports(sym_scope, pending)
            return render_prototype_driver(app_family, bound, sym_scope)
    if not prefer_kind_harness and not (multi_rejected and kind_name is not None) and entry in {guard_fn, cut_fn}:
        resolved = _resolve_guard_signatures(case_ir, sym_scope)
        if resolved:
            signatures, exports = resolved
            if exports:
                stored = list(sym_scope.get('static_exports') or [])
                stored.extend(exports)
                sym_scope['static_exports'] = stored
            if len(signatures) >= 2:
                return render_multi_caller_driver(app_family, signatures, sym_scope)
            return render_prototype_driver(app_family, signatures[0], sym_scope)
    if kind_name is None:
        raise ValueError(f'cut prototype not found: {entry}')

    kind = kind_name or guard_fn

    if kind == 'brotli_stream_refill':
        exp_state_h = str((Path(__file__).resolve().parents[2] / 'runtime/experiment/state.h').resolve())
        return (
            '#include "decode.c"\n'
            f'#include "{exp_state_h}"\n'
            'extern int __vulgate_table_set_current_input(uint64_t scope, uint64_t key, uint64_t val);\n'
        ) + '''
typedef struct vg_brotli_obs {
    int ret_code;
    size_t avail_out;
    size_t total_out;
    int pos;
    int partial_pos;
    uint8_t byte0;
} vg_brotli_obs;

static int vg_brotli_process_commands_caller(
    BrotliDecoderState *st, size_t *avail_out, uint8_t **next_out,
    size_t *total_out, vg_brotli_obs *obs)
{
    BrotliDecoderErrorCode rc = WriteRingBuffer(st, avail_out, next_out, total_out, BROTLI_TRUE);
    if ((int)rc < 0) {
        st->error_code = rc;
        obs->ret_code = (int)rc;
        obs->avail_out = *avail_out;
        obs->total_out = *total_out;
        obs->pos = st->pos;
        obs->partial_pos = (int)st->partial_pos_out;
        return BROTLI_DECODER_RESULT_ERROR;
    }
    obs->ret_code = (int)rc;
    obs->avail_out = *avail_out;
    obs->total_out = *total_out;
    obs->pos = st->pos;
    obs->partial_pos = (int)st->partial_pos_out;
    return BROTLI_DECODER_RESULT_SUCCESS;
}

static void vg_init_brotli(
    BrotliDecoderState *st, uint8_t *ring, uint8_t *inbuf, uint8_t *decoded,
    uint64_t pos_in, uint64_t rem_in, uint64_t occ_in, uint64_t unread_in)
{
    memset(st, 0, sizeof(*st));
    for (unsigned i = 0; i < 16; ++i) { ring[i] = (uint8_t)(65 + i); inbuf[i] = 0; decoded[i] = 0; }
    st->ringbuffer = ring;
    st->ringbuffer_size = 16;
    st->ringbuffer_mask = 15;
    st->window_bits = 4;
    st->pos = (int)pos_in;
    st->meta_block_remaining_len = (int)rem_in;
    st->buffer_length = (uint32_t)occ_in;
    st->br.next_in = inbuf;
    st->br.last_in = inbuf + unread_in;
}

int __vg_run_world_0(uint64_t pos_in, uint64_t rem_in, uint64_t occ_in,
                     uint64_t unread_in, uint64_t avail_in, uint64_t out_cap,
                     vg_brotli_obs *obs)
{
    (void)avail_in;
    BrotliDecoderState st;
    uint8_t ring[16], inbuf[16], decoded[16];
    vg_init_brotli(&st, ring, inbuf, decoded, pos_in, rem_in, occ_in, unread_in);
    size_t avail_out = (size_t)out_cap, total_out = 0;
    uint8_t *next_out = decoded;
    int r = vg_brotli_process_commands_caller(&st, &avail_out, &next_out, &total_out, obs);
    obs->byte0 = decoded[0];
    return r;
}

int __vg_run_world_1(uint64_t pos_in, uint64_t rem_in, uint64_t occ_in,
                     uint64_t unread_in, uint64_t avail_in, uint64_t out_cap,
                     vg_brotli_obs *obs)
{
    BrotliDecoderState st;
    uint8_t ring[16], inbuf[16], decoded[16];
    vg_init_brotli(&st, ring, inbuf, decoded, pos_in, rem_in, occ_in, unread_in);
    __vulgate_table_set_current_input(0, (uint64_t)(uintptr_t)&st, avail_in);
    size_t avail_out = (size_t)out_cap, total_out = 0;
    uint8_t *next_out = decoded;
    int r = vg_brotli_process_commands_caller(&st, &avail_out, &next_out, &total_out, obs);
    obs->byte0 = decoded[0];
    return r;
}

void __vg_verify_obligations(void) {
    uint64_t __vg_in_position = __vulgate_nondet_u64();
    uint64_t __vg_in_remaining = __vulgate_nondet_u64();
    uint64_t __vg_in_occupied = __vulgate_nondet_u64();
    uint64_t __vg_in_unread = __vulgate_nondet_u64();
    uint64_t __vg_in_available_in = __vulgate_nondet_u64();
    uint64_t __vg_in_output_capacity = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_position <= 16ULL && __vg_in_remaining <= 4ULL &&
                     __vg_in_occupied <= 8ULL && __vg_in_unread <= 8ULL &&
                     __vg_in_available_in <= 2ULL && __vg_in_output_capacity <= 16ULL);
    vg_brotli_obs obs1 = {0};
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    int res1 = __vg_run_world_1(__vg_in_position, __vg_in_remaining, __vg_in_occupied,
                                __vg_in_unread, __vg_in_available_in, __vg_in_output_capacity, &obs1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    _Bool bad_cap = (__vg_in_occupied > 8ULL) || (__vg_in_occupied == 0ULL && __vg_in_unread > 8ULL) ||
                    (__vg_in_occupied == 8ULL && __vg_in_unread > 0ULL && __vg_in_available_in > 0ULL);
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_position = __vulgate_nondet_u64();
    uint64_t __vg_in_remaining = __vulgate_nondet_u64();
    uint64_t __vg_in_occupied = __vulgate_nondet_u64();
    uint64_t __vg_in_unread = __vulgate_nondet_u64();
    uint64_t __vg_in_available_in = __vulgate_nondet_u64();
    uint64_t __vg_in_output_capacity = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_position <= 16ULL && __vg_in_remaining <= 4ULL &&
                     __vg_in_occupied <= 8ULL && __vg_in_unread <= 8ULL &&
                     __vg_in_available_in <= 2ULL && __vg_in_output_capacity <= 16ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    vg_brotli_obs obs0 = {0}, obs1 = {0};
    int r0 = __vg_run_world_0(__vg_in_position, __vg_in_remaining, __vg_in_occupied,
                              __vg_in_unread, __vg_in_available_in, __vg_in_output_capacity, &obs0);
    __vulgate_any_blocked = 0;
    int r1 = __vg_run_world_1(__vg_in_position, __vg_in_remaining, __vg_in_occupied,
                              __vg_in_unread, __vg_in_available_in, __vg_in_output_capacity, &obs1);
    _Bool __vg_obs_diff = (r0 != r1) || (obs0.ret_code != obs1.ret_code) ||
                          (obs0.avail_out != obs1.avail_out) || (obs0.total_out != obs1.total_out) ||
                          (obs0.pos != obs1.pos) || (obs0.byte0 != obs1.byte0);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'nginx_script_check_length':
        return NGINX_ENV_MODEL + '''
void ngx_http_script_copy_code(ngx_http_script_engine_t *e);

typedef struct vg_script_obs {
    ngx_int_t status;
    size_t pos_offset;
    int clean_exit;
} vg_script_obs;

static _Bool __vg_script_progress_check;

static void vg_script_engine_cut(uint64_t alloc_len, uint64_t reserved_len, uint64_t copy_len, vg_script_obs *obs) {
    ngx_http_request_t r; ngx_connection_t c; ngx_log_t log;
    ngx_pool_t pool;
    u_char pmem[64], code_buf[64], outbuf[64];
    ngx_http_script_engine_t e;
    memset(&r, 0, sizeof(r)); memset(&c, 0, sizeof(c)); memset(&log, 0, sizeof(log));
    memset(&pool, 0, sizeof(pool)); memset(&e, 0, sizeof(e));
    c.log = &log; r.connection = &c;
    pool.d.last = pmem; pool.d.end = pmem + sizeof(pmem); r.pool = &pool;
    memset(code_buf, 0, sizeof(code_buf));
    memset(outbuf, 0, sizeof(outbuf));
    ngx_http_script_copy_code_t *cc = (ngx_http_script_copy_code_t *)code_buf;
    cc->code = ngx_http_script_copy_code;
    cc->len = (uintptr_t)copy_len;
    e.ip = code_buf;
    e.pos = outbuf;
    e.end = outbuf + (size_t)alloc_len;
    e.request = &r;
    e.status = NGX_HTTP_OK;
    u_char *ip_before = e.ip;
    while (*(uintptr_t *) e.ip) {
        ngx_http_script_copy_code(&e);
        if (__vg_script_progress_check) {
            __CPROVER_assert(e.ip != ip_before || *(uintptr_t *)e.ip == 0, "vg.obligation.loop_exit_progress");
        }
        break;
    }
    obs->status = e.status;
    obs->pos_offset = (size_t)(e.pos - outbuf);
    obs->clean_exit = (*(uintptr_t *)e.ip == 0);
    (void)reserved_len;
}

int __vg_run_world_0(uint64_t alloc_len, uint64_t reserved_len, uint64_t copy_len, vg_script_obs *obs) {
    vg_script_engine_cut(alloc_len, reserved_len, copy_len, obs);
    return (int)obs->status;
}
int __vg_run_world_1(uint64_t alloc_len, uint64_t reserved_len, uint64_t copy_len, vg_script_obs *obs) {
    vg_script_engine_cut(alloc_len, reserved_len, copy_len, obs);
    return (int)obs->status;
}

void __vg_verify_obligations(void) {
    __vg_script_progress_check = 1;
    uint64_t __vg_in_alloc_len = __vulgate_nondet_u64();
    uint64_t __vg_in_reserved = __vulgate_nondet_u64();
    uint64_t __vg_in_length = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_alloc_len >= 4ULL && __vg_in_alloc_len <= 16ULL);
    __CPROVER_assume(__vg_in_reserved >= 1ULL && __vg_in_reserved <= __vg_in_alloc_len);
    __CPROVER_assume(__vg_in_length <= 16ULL);
    vg_script_obs obs0 = {0}, obs1 = {0};
    __vg_run_world_0(__vg_in_alloc_len, __vg_in_reserved, __vg_in_length, &obs0);
    if (obs0.pos_offset > (__vg_in_alloc_len - __vg_in_reserved)) {
        __CPROVER_assert(0, "vg.target.nonvacuity_w0");
    }
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    __vg_run_world_1(__vg_in_alloc_len, __vg_in_reserved, __vg_in_length, &obs1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_length = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_length <= 8ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    vg_script_obs obs0 = {0}, obs1 = {0};
    __vg_run_world_0(16ULL, 0ULL, __vg_in_length, &obs0);
    __vulgate_any_blocked = 0;
    __vg_run_world_1(16ULL, 0ULL, __vg_in_length, &obs1);
    _Bool __vg_obs_diff = (obs0.status != obs1.status) || (obs0.pos_offset != obs1.pos_offset);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'nginx_script_regex_start':
        return NGINX_ENV_MODEL + '''
void ngx_http_script_regex_start_code(ngx_http_script_engine_t *e);
ngx_int_t ngx_http_regex_exec(ngx_http_request_t *r, ngx_http_regex_t *re, ngx_str_t *s) {
    (void)r; (void)re; (void)s; return NGX_DECLINED;
}

typedef struct vg_regex_script_obs {
    ngx_int_t status;
    int clean_exit;
} vg_regex_script_obs;

static void vg_regex_script_cut(uint64_t invoke_regex, vg_regex_script_obs *obs) {
    ngx_http_request_t r; ngx_connection_t c; ngx_log_t log;
    memset(&r, 0, sizeof(r)); memset(&c, 0, sizeof(c)); memset(&log, 0, sizeof(log));
    c.log = &log; r.connection = &c;
    u_char code_buf[256] = {0};
    ngx_http_script_regex_code_t *rc = (ngx_http_script_regex_code_t *)code_buf;
    rc->code = invoke_regex ? ngx_http_script_regex_start_code : NULL;
    rc->next = sizeof(ngx_http_script_regex_code_t);
    ngx_http_script_engine_t e;
    memset(&e, 0, sizeof(e));
    ngx_http_variable_value_t sp_slots[4];
    memset(sp_slots, 0, sizeof(sp_slots));
    static u_char vg_sp_lit[] = "1";
    sp_slots[1].len = 1;
    sp_slots[1].data = vg_sp_lit;
    e.sp = &sp_slots[2];
    e.ip = code_buf;
    e.request = &r;
    e.status = NGX_HTTP_OK;
    while (*(uintptr_t *)e.ip) {
        if ((void *)e.ip == (void *)code_buf && invoke_regex) {
            ngx_http_script_regex_start_code(&e);
        } else {
            break;
        }
    }
    obs->status = e.status;
    obs->clean_exit = (*(uintptr_t *)e.ip == 0);
}

int __vg_run_world_0(uint64_t invoke_regex, vg_regex_script_obs *obs) {
    vg_regex_script_cut(invoke_regex, obs);
    return (int)obs->status;
}
int __vg_run_world_1(uint64_t invoke_regex, vg_regex_script_obs *obs) {
    vg_regex_script_cut(invoke_regex, obs);
    return (int)obs->status;
}

void __vg_verify_obligations(void) {
    uint64_t __vg_in_invoke_regex = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_invoke_regex <= 1ULL);
    vg_regex_script_obs obs1 = {0};
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    __vg_run_world_1(__vg_in_invoke_regex, &obs1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_invoke_regex = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_invoke_regex <= 1ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    vg_regex_script_obs obs0 = {0}, obs1 = {0};
    __vg_run_world_0(__vg_in_invoke_regex, &obs0);
    __vulgate_any_blocked = 0;
    __vg_run_world_1(__vg_in_invoke_regex, &obs1);
    _Bool __vg_obs_diff = (obs0.status != obs1.status);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'nginx_alias_map_uri':
        return NGINX_ENV_MODEL + '''
u_char *ngx_http_map_uri_to_path(ngx_http_request_t *r, ngx_str_t *path, size_t *root_length, size_t reserved);
u_char *ngx_http_script_run(ngx_http_request_t *r, ngx_str_t *value, void *code_lengths, size_t len, void *code_values) {
    (void)r; (void)value; (void)code_lengths; (void)len; (void)code_values; return NULL;
}

typedef struct vg_alias_obs {
    ngx_int_t rc;
    int path_allocated;
    size_t root_len;
} vg_alias_obs;

static ngx_int_t vg_static_content_caller(ngx_http_request_t *r, vg_alias_obs *obs) {
    size_t root = 0;
    ngx_str_t path = {0, NULL};
    u_char *last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        obs->rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
        obs->path_allocated = (path.data != NULL);
        obs->root_len = root;
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    obs->rc = NGX_OK;
    obs->path_allocated = (path.data != NULL);
    obs->root_len = root;
    return NGX_OK;
}

static void vg_setup_alias(ngx_http_request_t *r, ngx_connection_t *c, ngx_log_t *log,
                           void **loc_confs, ngx_http_core_loc_conf_t *clcf,
                           ngx_pool_t *pool, u_char *pmem, u_char *ubuf, u_char *rbuf,
                           uint64_t alias_v, uint64_t valid_loc, uint64_t uri_chg)
{
    memset(r, 0, sizeof(*r)); memset(c, 0, sizeof(*c)); memset(log, 0, sizeof(*log));
    memset(clcf, 0, sizeof(*clcf)); memset(pool, 0, sizeof(*pool));
    memset(pmem, 0, 64);
    for (unsigned i = 0; i < 8; ++i) { ubuf[i] = 'a'; rbuf[i] = '/'; }
    c->log = log; r->connection = c;
    pool->d.last = pmem; pool->d.end = pmem + 64; pool->current = pool; pool->max = 64;
    r->pool = pool;
    ngx_http_core_module.ctx_index = 0;
    loc_confs[0] = clcf;
    r->loc_conf = loc_confs;
    clcf->alias = (size_t)alias_v;
    clcf->root.len = 4; clcf->root.data = rbuf;
    clcf->name.len = 4; clcf->name.data = rbuf;
    r->uri.len = 6; r->uri.data = ubuf;
    r->valid_location = valid_loc ? 1 : 0;
    r->uri_changed = uri_chg ? 1 : 0;
}

int __vg_run_world_0(uint64_t alias_v, uint64_t valid_loc, uint64_t uri_chg, vg_alias_obs *obs) {
    ngx_http_request_t r; ngx_connection_t c; ngx_log_t log;
    void *lconfs[2] = {0}; ngx_http_core_loc_conf_t clcf;
    ngx_pool_t pool; u_char pmem[64], ubuf[8], rbuf[8];
    vg_setup_alias(&r, &c, &log, lconfs, &clcf, &pool, pmem, ubuf, rbuf, alias_v, valid_loc, uri_chg);
    return (int)vg_static_content_caller(&r, obs);
}
int __vg_run_world_1(uint64_t alias_v, uint64_t valid_loc, uint64_t uri_chg, vg_alias_obs *obs) {
    ngx_http_request_t r; ngx_connection_t c; ngx_log_t log;
    void *lconfs[2] = {0}; ngx_http_core_loc_conf_t clcf;
    ngx_pool_t pool; u_char pmem[64], ubuf[8], rbuf[8];
    vg_setup_alias(&r, &c, &log, lconfs, &clcf, &pool, pmem, ubuf, rbuf, alias_v, valid_loc, uri_chg);
    return (int)vg_static_content_caller(&r, obs);
}

void __vg_verify_obligations(void) {
    uint64_t __vg_in_alias = __vulgate_nondet_u64();
    uint64_t __vg_in_valid_loc = __vulgate_nondet_u64();
    uint64_t __vg_in_uri_changed = __vulgate_nondet_u64();
    __CPROVER_assume((__vg_in_alias == 0ULL || __vg_in_alias == 4ULL) && __vg_in_valid_loc <= 1ULL && __vg_in_uri_changed <= 1ULL);
    vg_alias_obs obs0 = {0}, obs1 = {0};
    __vg_run_world_0(__vg_in_alias, __vg_in_valid_loc, __vg_in_uri_changed, &obs0);
    if (__vg_in_alias != 0ULL && __vg_in_uri_changed != 0ULL && obs0.rc == NGX_OK) {
        __CPROVER_assert(0, "vg.target.nonvacuity_w0");
    }
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    __vg_run_world_1(__vg_in_alias, __vg_in_valid_loc, __vg_in_uri_changed, &obs1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_alias = __vulgate_nondet_u64();
    uint64_t __vg_in_flags = __vulgate_nondet_u64();
    __CPROVER_assume((__vg_in_alias == 0ULL || __vg_in_alias == 4ULL) && (__vg_in_flags == 0ULL || __vg_in_flags == 1ULL));
    /*VG_IMPACT_REGION_ASSUME*/
    vg_alias_obs obs0 = {0}, obs1 = {0};
    __vg_run_world_0(__vg_in_alias, 1ULL, __vg_in_flags, &obs0);
    __vulgate_any_blocked = 0;
    __vg_run_world_1(__vg_in_alias, 1ULL, __vg_in_flags, &obs1);
    _Bool __vg_obs_diff = (obs0.rc != obs1.rc) || (obs0.path_allocated != obs1.path_allocated);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'nginx_copy_filter_aio':
        return NGINX_ENV_MODEL + '''
#include "ngx_http_copy_filter_module.c"
ngx_http_output_body_filter_pt ngx_http_top_body_filter = NULL;
ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in) {
    if (ctx && ctx->filter_ctx) {
        ngx_http_request_t *r = (ngx_http_request_t *)ctx->filter_ctx;
        if (in && r->main && r->main->blocked < 255) {
            r->main->blocked++;
        }
    }
    return NGX_OK;
}
ngx_uint_t ngx_file_aio = 0;

typedef struct vg_aio_obs {
    ngx_int_t rc;
    unsigned blocked_after;
} vg_aio_obs;

static ngx_int_t vg_output_body_caller(ngx_http_request_t *r, ngx_chain_t *in, vg_aio_obs *obs) {
    ngx_int_t rc = ngx_http_copy_filter(r, in);
    obs->rc = rc;
    obs->blocked_after = r->main->blocked;
    return rc;
}

static void vg_setup_aio(ngx_http_request_t *r, ngx_http_request_t *main_r, ngx_connection_t *c,
                         ngx_log_t *log, void **ctxs, void **lconfs, ngx_http_core_loc_conf_t *clcf,
                         ngx_http_copy_filter_conf_t *cfconf, ngx_pool_t *pool, u_char *pmem,
                         uint64_t blocked_init)
{
    memset(r, 0, sizeof(*r)); memset(main_r, 0, sizeof(*main_r));
    memset(c, 0, sizeof(*c)); memset(log, 0, sizeof(*log));
    memset(clcf, 0, sizeof(*clcf)); memset(cfconf, 0, sizeof(*cfconf)); memset(pool, 0, sizeof(*pool));
    memset(pmem, 0, 128);
    c->log = log; r->connection = c; r->main = main_r;
    main_r->blocked = (unsigned)(blocked_init & 255ULL);
    pool->d.last = pmem; pool->d.end = pmem + 128; pool->current = pool; pool->max = 128;
    r->pool = pool;
    ngx_http_core_module.ctx_index = 0;
    ngx_http_copy_filter_module.ctx_index = 1;
    lconfs[0] = clcf; lconfs[1] = cfconf;
    ctxs[0] = NULL; ctxs[1] = NULL;
    r->loc_conf = lconfs; r->ctx = ctxs;
}

int __vg_run_world_0(uint64_t blocked_init, vg_aio_obs *obs) {
    ngx_http_request_t r, main_r; ngx_connection_t c; ngx_log_t log;
    void *ctxs[2], *lconfs[2]; ngx_http_core_loc_conf_t clcf; ngx_http_copy_filter_conf_t cfconf;
    ngx_pool_t pool; u_char pmem[128]; ngx_chain_t chain; ngx_buf_t buf;
    memset(&chain, 0, sizeof(chain)); memset(&buf, 0, sizeof(buf)); chain.buf = &buf;
    vg_setup_aio(&r, &main_r, &c, &log, ctxs, lconfs, &clcf, &cfconf, &pool, pmem, blocked_init);
    return (int)vg_output_body_caller(&r, &chain, obs);
}
int __vg_run_world_1(uint64_t blocked_init, vg_aio_obs *obs) {
    ngx_http_request_t r, main_r; ngx_connection_t c; ngx_log_t log;
    void *ctxs[2], *lconfs[2]; ngx_http_core_loc_conf_t clcf; ngx_http_copy_filter_conf_t cfconf;
    ngx_pool_t pool; u_char pmem[128]; ngx_chain_t chain; ngx_buf_t buf;
    memset(&chain, 0, sizeof(chain)); memset(&buf, 0, sizeof(buf)); chain.buf = &buf;
    vg_setup_aio(&r, &main_r, &c, &log, ctxs, lconfs, &clcf, &cfconf, &pool, pmem, blocked_init);
    return (int)vg_output_body_caller(&r, &chain, obs);
}

void __vg_verify_obligations(void) {
    uint64_t __vg_in_counter = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_counter <= 255ULL);
    vg_aio_obs obs1 = {0};
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    int rc1 = __vg_run_world_1(__vg_in_counter, &obs1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_counter = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_counter <= 254ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    vg_aio_obs obs0 = {0}, obs1 = {0};
    int r0 = __vg_run_world_0(__vg_in_counter, &obs0);
    __vulgate_any_blocked = 0;
    int r1 = __vg_run_world_1(__vg_in_counter, &obs1);
    _Bool __vg_obs_diff = (r0 != r1) || (obs0.blocked_after != obs1.blocked_after);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'nginx_map_variable':
        return NGINX_ENV_MODEL + '''
#include "ngx_http_map_module.c"
ngx_int_t ngx_http_complex_value(ngx_http_request_t *r, ngx_http_complex_value_t *val, ngx_str_t *value) {
    (void)r; (void)val;
    static u_char lit[] = "key";
    value->len = 3; value->data = lit;
    return NGX_OK;
}
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key, u_char *name, size_t len) {
    (void)hash; (void)key; (void)name; (void)len; return NULL;
}
void *ngx_http_map_find(ngx_http_request_t *r, ngx_http_map_t *map, ngx_str_t *match) {
    u_char *low = NULL;
    size_t len;
    void *value;
    if (map == NULL || match == NULL) return NULL;
    len = match->len;
    if (len) {
        if (r == NULL || r->pool == NULL || match->data == NULL || len > 3) return NULL;
        low = ngx_pnalloc(r->pool, len);
        if (low == NULL) return NULL;
        memcpy(low, match->data, len);
    }
    value = ngx_hash_find_combined(&map->hash, (ngx_uint_t)len, low, len);
    if (value != NULL) return value;
#if (NGX_PCRE)
    if (len && map->nregex && map->regex != NULL) {
        ngx_uint_t i;
        ngx_uint_t limit = map->nregex;
        if (limit > 4) limit = 4;
        for (i = 0; i < limit; i++) {
            ngx_int_t n = ngx_http_regex_exec(r, map->regex[i].regex, match);
            if (n == NGX_OK && map->regex[i].value != NULL) return map->regex[i].value;
            if (n != NGX_DECLINED) return NULL;
        }
    }
#endif
    return NULL;
}
ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len) { (void)data; return (ngx_uint_t)len; }
ngx_int_t ngx_http_regex_exec(ngx_http_request_t *r, ngx_http_regex_t *re, ngx_str_t *s) {
    (void)r; (void)re; (void)s; return NGX_DECLINED;
}
ngx_int_t ngx_http_compile_complex_value(ngx_http_compile_complex_value_t *ccv) { (void)ccv; return NGX_OK; }
ngx_http_variable_t *ngx_http_add_variable(ngx_conf_t *cf, ngx_str_t *name, ngx_uint_t flags) {
    (void)cf; (void)name; (void)flags; return NULL;
}
ngx_int_t ngx_http_get_variable_index(ngx_conf_t *cf, ngx_str_t *name) { (void)cf; (void)name; return 0; }
ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type) { (void)ha; (void)type; return NGX_OK; }
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key, void *value, ngx_uint_t flags) {
    (void)ha; (void)key; (void)value; (void)flags; return NGX_OK;
}
ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names, ngx_uint_t nelts) {
    (void)hinit; (void)names; (void)nelts; return NGX_OK;
}
ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names, ngx_uint_t nelts) {
    (void)hinit; (void)names; (void)nelts; return NGX_OK;
}
char *ngx_conf_set_num_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) { (void)cf; (void)cmd; (void)conf; return NULL; }
void ngx_conf_log_error(ngx_uint_t level, ngx_conf_t *cf, ngx_err_t err, const char *fmt, ...) { (void)level; (void)cf; (void)err; (void)fmt; }
char *ngx_conf_include(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) { (void)cf; (void)cmd; (void)conf; return NULL; }
ngx_http_regex_t *ngx_http_regex_compile(ngx_conf_t *cf, ngx_regex_compile_t *rc) { (void)cf; (void)rc; return NULL; }
void *ngx_array_push(ngx_array_t *a) { (void)a; return NULL; }
void *ngx_list_push(ngx_list_t *list) { (void)list; return NULL; }
ngx_pool_t *ngx_create_pool(size_t size, ngx_log_t *log) { (void)size; (void)log; return NULL; }
void ngx_destroy_pool(ngx_pool_t *pool) { (void)pool; }
ngx_int_t ngx_atoi(u_char *line, size_t n) { (void)line; (void)n; return 0; }
u_char *ngx_strlchr(u_char *p, u_char *last, u_char c) { (void)p; (void)last; (void)c; return NULL; }

typedef struct vg_map_obs {
    int var_valid;
    unsigned var_len;
} vg_map_obs;

static int vg_get_indexed_var_caller(uint64_t use_map_var, vg_map_obs *obs) {
    ngx_http_request_t r; ngx_connection_t c; ngx_log_t log; ngx_pool_t pool; u_char pmem[64];
    memset(&r, 0, sizeof(r)); memset(&c, 0, sizeof(c)); memset(&log, 0, sizeof(log)); memset(&pool, 0, sizeof(pool));
    pool.d.last = pmem; pool.d.end = pmem + sizeof(pmem);
    c.log = &log; r.connection = &c; r.pool = &pool;
    ngx_http_variable_value_t dflt, slot;
    static u_char dstr[] = "ordinary";
    memset(&dflt, 0, sizeof(dflt)); memset(&slot, 0, sizeof(slot));
    dflt.valid = 1; dflt.len = 8; dflt.data = dstr;
    ngx_http_map_ctx_t mctx;
    memset(&mctx, 0, sizeof(mctx));
    mctx.default_value = &dflt;
    if (!use_map_var) {
        obs->var_valid = 1; obs->var_len = 7;
        return 0;
    }
    if (ngx_http_map_variable(&r, &slot, (uintptr_t)&mctx) != NGX_OK) {
        slot.not_found = 1;
        obs->var_valid = 0; obs->var_len = 0;
        return -1;
    }
    obs->var_valid = slot.valid;
    obs->var_len = slot.len;
    return 0;
}

int __vg_run_world_0(uint64_t use_map_var, vg_map_obs *obs) { return vg_get_indexed_var_caller(use_map_var, obs); }
int __vg_run_world_1(uint64_t use_map_var, vg_map_obs *obs) { return vg_get_indexed_var_caller(use_map_var, obs); }

void __vg_verify_obligations(void) {
    uint64_t __vg_in_use_map = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_use_map <= 1ULL);
    vg_map_obs obs1 = {0};
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    int rc1 = __vg_run_world_1(__vg_in_use_map, &obs1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_use_map = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_use_map <= 1ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    vg_map_obs obs0 = {0}, obs1 = {0};
    int r0 = __vg_run_world_0(__vg_in_use_map, &obs0);
    __vulgate_any_blocked = 0;
    int r1 = __vg_run_world_1(__vg_in_use_map, &obs1);
    _Bool __vg_obs_diff = (r0 != r1) || (obs0.var_valid != obs1.var_valid);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'nginx_regex_captures':
        return NGINX_ENV_MODEL + '''
ngx_int_t ngx_http_regex_exec(ngx_http_request_t *r, ngx_http_regex_t *re, ngx_str_t *s);
ngx_int_t ngx_regex_exec(ngx_regex_t *re, ngx_str_t *s, int *captures, ngx_uint_t size) {
    (void)re; (void)s;
    if (captures && size >= 2) { captures[0] = 0; captures[1] = 3; return 1; }
    return NGX_REGEX_NO_MATCHED;
}

typedef struct vg_cap_obs {
    ngx_int_t rc;
    ngx_uint_t ncaptures_after;
} vg_cap_obs;

static ngx_int_t vg_regex_caller(uint64_t prior_ncap, uint64_t realloc_flag, vg_cap_obs *obs) {
    ngx_http_request_t r; ngx_connection_t c; ngx_log_t log;
    void *mconfs[2] = {0}; ngx_http_core_main_conf_t cmcf;
    ngx_pool_t pool; u_char pmem[128] = {0};
    int old_caps[4] = {0, 1, 0, 1};
    ngx_http_regex_t re; ngx_str_t s; static u_char sdata[] = "abc";
    memset(&r, 0, sizeof(r)); memset(&c, 0, sizeof(c)); memset(&log, 0, sizeof(log));
    memset(&cmcf, 0, sizeof(cmcf)); memset(&pool, 0, sizeof(pool)); memset(&re, 0, sizeof(re));
    c.log = &log; r.connection = &c;
    pool.d.last = pmem; pool.d.end = pmem + 128; pool.current = &pool; pool.max = 128;
    r.pool = &pool;
    ngx_http_core_module.ctx_index = 0;
    cmcf.ncaptures = 4;
    mconfs[0] = &cmcf; r.main_conf = mconfs;
    r.ncaptures = (ngx_uint_t)prior_ncap;
    r.captures = old_caps;
    r.realloc_captures = realloc_flag ? 1 : 0;
    re.ncaptures = 2; re.nvariables = 0;
    s.len = 3; s.data = sdata;
    ngx_int_t rc = ngx_http_regex_exec(&r, &re, &s);
    obs->rc = rc;
    obs->ncaptures_after = r.ncaptures;
    return rc;
}

int __vg_run_world_0(uint64_t prior_ncap, uint64_t realloc_flag, vg_cap_obs *obs) {
    return (int)vg_regex_caller(prior_ncap, realloc_flag, obs);
}
int __vg_run_world_1(uint64_t prior_ncap, uint64_t realloc_flag, vg_cap_obs *obs) {
    return (int)vg_regex_caller(prior_ncap, realloc_flag, obs);
}

void __vg_verify_obligations(void) {
    uint64_t __vg_in_captures = __vulgate_nondet_u64();
    uint64_t __vg_in_realloc = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_captures <= 4ULL && __vg_in_realloc <= 1ULL);
    vg_cap_obs obs1 = {0};
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    int rc1 = __vg_run_world_1(__vg_in_captures, __vg_in_realloc, &obs1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_captures = __vulgate_nondet_u64();
    uint64_t __vg_in_realloc = __vulgate_nondet_u64();
    __CPROVER_assume((__vg_in_captures == 0ULL || __vg_in_captures == 2ULL) && __vg_in_realloc <= 1ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    vg_cap_obs obs0 = {0}, obs1 = {0};
    int r0 = __vg_run_world_0(__vg_in_captures, __vg_in_realloc, &obs0);
    __vulgate_any_blocked = 0;
    int r1 = __vg_run_world_1(__vg_in_captures, __vg_in_realloc, &obs1);
    _Bool __vg_obs_diff = (r0 != r1);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'nginx_h2_grpc_serializers':
        return NGINX_ENV_MODEL + '''
ngx_int_t ngx_http_proxy_v2_create_request(ngx_http_request_t *r) {
    if (!r || !r->upstream) return NGX_ERROR;
    r->upstream->request_sent = 0;
    return NGX_OK;
}
ngx_int_t ngx_http_grpc_create_request(ngx_http_request_t *r) {
    if (!r || !r->upstream) return NGX_ERROR;
    r->upstream->request_sent = 0;
    return NGX_OK;
}

typedef struct vg_up_obs {
    ngx_int_t finalized_status;
    int serialized;
} vg_up_obs;

static void vg_upstream_init_request_cut(uint64_t proto_mode, vg_up_obs *obs) {
    ngx_http_request_t r; ngx_http_upstream_t u;
    memset(&r, 0, sizeof(r)); memset(&u, 0, sizeof(u));
    r.upstream = &u;
    ngx_int_t rc = NGX_OK;
    if (proto_mode == 1ULL) {
        rc = ngx_http_proxy_v2_create_request(&r);
    } else if (proto_mode == 2ULL) {
        rc = ngx_http_grpc_create_request(&r);
    }
    if (rc != NGX_OK) {
        obs->finalized_status = NGX_HTTP_INTERNAL_SERVER_ERROR;
        obs->serialized = 0;
        return;
    }
    obs->finalized_status = NGX_HTTP_OK;
    obs->serialized = 1;
}

int __vg_run_world_0(uint64_t proto_mode, vg_up_obs *obs) {
    vg_upstream_init_request_cut(proto_mode, obs);
    return (int)obs->finalized_status;
}
int __vg_run_world_1(uint64_t proto_mode, vg_up_obs *obs) {
    vg_upstream_init_request_cut(proto_mode, obs);
    return (int)obs->finalized_status;
}

void __vg_verify_obligations(void) {
    uint64_t __vg_in_proto_mode = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_proto_mode <= 2ULL);
    vg_up_obs obs1 = {0};
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    __vg_run_world_1(__vg_in_proto_mode, &obs1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_proto_mode = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_proto_mode <= 2ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    vg_up_obs obs0 = {0}, obs1 = {0};
    __vg_run_world_0(__vg_in_proto_mode, &obs0);
    __vulgate_any_blocked = 0;
    __vg_run_world_1(__vg_in_proto_mode, &obs1);
    _Bool __vg_obs_diff = (obs0.finalized_status != obs1.finalized_status) || (obs0.serialized != obs1.serialized);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'nginx_dav_copy_move':
        return NGINX_ENV_MODEL + '''
ngx_int_t ngx_http_dav_copy_move_handler(ngx_http_request_t *r) {
    if (!r->headers_in.destination) return NGX_HTTP_BAD_REQUEST;
    return NGX_HTTP_NO_CONTENT;
}

static ngx_int_t vg_dav_handler_cut(uint64_t method) {
    ngx_http_request_t r; ngx_table_elt_t dest;
    memset(&r, 0, sizeof(r)); memset(&dest, 0, sizeof(dest));
    r.method = (ngx_uint_t)method;
    r.headers_in.destination = &dest;
    if (r.method == NGX_HTTP_COPY || r.method == NGX_HTTP_MOVE) {
        return ngx_http_dav_copy_move_handler(&r);
    }
    return NGX_DECLINED;
}

int __vg_run_world_0(uint64_t method) { return (int)vg_dav_handler_cut(method); }
int __vg_run_world_1(uint64_t method) { return (int)vg_dav_handler_cut(method); }

void __vg_verify_obligations(void) {
    uint64_t __vg_in_method = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_method == NGX_HTTP_GET || __vg_in_method == NGX_HTTP_COPY || __vg_in_method == NGX_HTTP_MOVE);
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    int rc1 = __vg_run_world_1(__vg_in_method);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_method = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_method == NGX_HTTP_GET || __vg_in_method == NGX_HTTP_COPY);
    /*VG_IMPACT_REGION_ASSUME*/
    int r0 = __vg_run_world_0(__vg_in_method);
    __vulgate_any_blocked = 0;
    int r1 = __vg_run_world_1(__vg_in_method);
    _Bool __vg_obs_diff = (r0 != r1);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'httpd_vhost_translate':
        return HTTPD_ENV_MODEL + '''
int mva_translate(request_rec *r) {
    if (!r->uri || r->uri[0] != '/') return DECLINED;
    r->filename = "/var/www/index.html";
    return OK;
}

static int vg_ap_translate_name_cut(uint64_t uri_is_slash, int *filename_set) {
    request_rec r;
    memset(&r, 0, sizeof(r));
    r.uri = uri_is_slash ? "/plain.txt" : "asterisk";
    int rc = mva_translate(&r);
    *filename_set = (r.filename != NULL);
    return rc;
}

int __vg_run_world_0(uint64_t uri_is_slash, int *fset) { return vg_ap_translate_name_cut(uri_is_slash, fset); }
int __vg_run_world_1(uint64_t uri_is_slash, int *fset) { return vg_ap_translate_name_cut(uri_is_slash, fset); }

void __vg_verify_obligations(void) {
    uint64_t __vg_in_is_slash = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_is_slash <= 1ULL);
    int fset1 = 0;
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    int rc1 = __vg_run_world_1(__vg_in_is_slash, &fset1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_is_slash = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_is_slash <= 1ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    int f0 = 0, f1 = 0;
    int r0 = __vg_run_world_0(__vg_in_is_slash, &f0);
    __vulgate_any_blocked = 0;
    int r1 = __vg_run_world_1(__vg_in_is_slash, &f1);
    _Bool __vg_obs_diff = (r0 != r1) || (f0 != f1);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'httpd_h2_c1_setup':
        return HTTPD_ENV_MODEL + '''
apr_status_t h2_c1_setup(conn_rec *c, request_rec *r, server_rec *s) {
    (void)c; (void)r; (void)s;
    return APR_SUCCESS;
}

static int vg_h2_process_conn_cut(uint64_t is_h2_proto, int *detached) {
    conn_rec c; server_rec s;
    memset(&c, 0, sizeof(c)); memset(&s, 0, sizeof(s));
    c.base_server = &s;
    *detached = 0;
    if (!is_h2_proto) return DECLINED;
    apr_status_t st = h2_c1_setup(&c, NULL, &s);
    if (st != APR_SUCCESS) {
        *detached = 1;
        return !OK;
    }
    return OK;
}

int __vg_run_world_0(uint64_t is_h2_proto, int *det) { return vg_h2_process_conn_cut(is_h2_proto, det); }
int __vg_run_world_1(uint64_t is_h2_proto, int *det) { return vg_h2_process_conn_cut(is_h2_proto, det); }

void __vg_verify_obligations(void) {
    uint64_t __vg_in_is_h2 = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_is_h2 <= 1ULL);
    int det1 = 0;
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    int rc1 = __vg_run_world_1(__vg_in_is_h2, &det1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_is_h2 = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_is_h2 <= 1ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    int d0 = 0, d1 = 0;
    int r0 = __vg_run_world_0(__vg_in_is_h2, &d0);
    __vulgate_any_blocked = 0;
    int r1 = __vg_run_world_1(__vg_in_is_h2, &d1);
    _Bool __vg_obs_diff = (r0 != r1) || (d0 != d1);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'httpd_dav_proppatch':
        return HTTPD_ENV_MODEL + '''
int dav_method_proppatch(request_rec *r) {
    (void)r;
    return 207;
}

static int vg_dav_handler_cut(uint64_t method_num) {
    request_rec r;
    memset(&r, 0, sizeof(r));
    r.method_number = (int)method_num;
    if (r.method_number == M_PROPPATCH) {
        return dav_method_proppatch(&r);
    }
    return OK;
}

int __vg_run_world_0(uint64_t m) { return vg_dav_handler_cut(m); }
int __vg_run_world_1(uint64_t m) { return vg_dav_handler_cut(m); }

void __vg_verify_obligations(void) {
    uint64_t __vg_in_method = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_method == M_GET || __vg_in_method == M_PROPPATCH);
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    int rc1 = __vg_run_world_1(__vg_in_method);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_method = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_method == M_GET || __vg_in_method == M_PROPPATCH);
    /*VG_IMPACT_REGION_ASSUME*/
    int r0 = __vg_run_world_0(__vg_in_method);
    __vulgate_any_blocked = 0;
    int r1 = __vg_run_world_1(__vg_in_method);
    _Bool __vg_obs_diff = (r0 != r1);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'httpd_session_proxy':
        return HTTPD_ENV_MODEL + '''
int proxy_handler(request_rec *r) {
    if (!r->filename) return DECLINED;
    return OK;
}

static int vg_invoke_handler_cut(uint64_t has_prev) {
    request_rec r, prev_r;
    memset(&r, 0, sizeof(r)); memset(&prev_r, 0, sizeof(prev_r));
    r.filename = "proxy:http://127.0.0.1/plain";
    r.prev = has_prev ? &prev_r : NULL;
    return proxy_handler(&r);
}

int __vg_run_world_0(uint64_t has_prev) { return vg_invoke_handler_cut(has_prev); }
int __vg_run_world_1(uint64_t has_prev) { return vg_invoke_handler_cut(has_prev); }

void __vg_verify_obligations(void) {
    uint64_t __vg_in_previous = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_previous <= 1ULL);
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    int rc1 = __vg_run_world_1(__vg_in_previous);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_previous = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_previous <= 1ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    int r0 = __vg_run_world_0(__vg_in_previous);
    __vulgate_any_blocked = 0;
    int r1 = __vg_run_world_1(__vg_in_previous);
    _Bool __vg_obs_diff = (r0 != r1);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind in ('httpd_xml2enc_filter', 'httpd_charset_out_filter'):
        fn_name = 'xml2enc_ffunc' if kind == 'httpd_xml2enc_filter' else 'xlate_out_filter'
        extra_in_caller = ''
        if kind == 'httpd_charset_out_filter':
            extra_in_caller = '''
static apr_status_t finish_partial_char_sink(void) { return APR_SUCCESS; }
apr_status_t xlate_in_filter(ap_filter_t *f, apr_bucket_brigade *bb) {
    (void)f; (void)bb; return finish_partial_char_sink();
}
'''
        return HTTPD_ENV_MODEL + extra_in_caller + f'''
apr_status_t {fn_name}(ap_filter_t *f, apr_bucket_brigade *bb) {{
    (void)f; (void)bb;
    return APR_SUCCESS;
}}

static apr_status_t vg_ap_pass_brigade_cut(uint64_t filter_enabled) {{
    ap_filter_t f; request_rec r;
    apr_pool_t *pool = (apr_pool_t *)__vg_pool_token;
    apr_bucket_alloc_t *alloc;
    apr_bucket_brigade *bb;
    memset(&f, 0, sizeof(f)); memset(&r, 0, sizeof(r));
    f.r = &r;
    alloc = apr_bucket_alloc_create(pool);
    bb = apr_brigade_create(pool, alloc);
    if (!bb || !__vg_brigade_consistent(bb)) return APR_ENOMEM;
    if (!filter_enabled) return APR_SUCCESS;
    return {fn_name}(&f, bb);
}}

int __vg_run_world_0(uint64_t en) {{ return (int)vg_ap_pass_brigade_cut(en); }}
int __vg_run_world_1(uint64_t en) {{ return (int)vg_ap_pass_brigade_cut(en); }}

void __vg_verify_obligations(void) {{
    uint64_t __vg_in_filter_en = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_filter_en <= 1ULL);
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    int rc1 = __vg_run_world_1(__vg_in_filter_en);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}}

void __vg_impact_harness(void) {{
    uint64_t __vg_in_filter_en = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_filter_en <= 1ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    int r0 = __vg_run_world_0(__vg_in_filter_en);
    __vulgate_any_blocked = 0;
    int r1 = __vg_run_world_1(__vg_in_filter_en);
    _Bool __vg_obs_diff = (r0 != r1);
    /*VG_IMPACT_QUERY_ASSERT*/
}}
'''

    if kind == 'httpd_proxy_html_comment':
        return HTTPD_ENV_MODEL + '''
typedef struct vg_sax_ctx {
    int emitted_comment;
    int emitted_body;
    int flushed_early;
} vg_sax_ctx;

void pcomment(void *ctxt, const unsigned char *uchars) {
    vg_sax_ctx *ctx = (vg_sax_ctx *)ctxt;
    if (uchars && uchars[0]) {
        ctx->emitted_comment = 1;
        ctx->flushed_early = 1;
    }
}

static void vg_proxy_html_sax_cut(uint64_t has_comment, vg_sax_ctx *ctx) {
    ctx->emitted_body = 1;
    if (has_comment) {
        static const unsigned char cmt[] = "ordinary";
        pcomment(ctx, cmt);
    }
}

int __vg_run_world_0(uint64_t has_comment, vg_sax_ctx *ctx) { vg_proxy_html_sax_cut(has_comment, ctx); return ctx->emitted_body; }
int __vg_run_world_1(uint64_t has_comment, vg_sax_ctx *ctx) { vg_proxy_html_sax_cut(has_comment, ctx); return ctx->emitted_body; }

void __vg_verify_obligations(void) {
    uint64_t __vg_in_has_comment = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_has_comment <= 1ULL);
    vg_sax_ctx ctx1 = {0};
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    __vg_run_world_1(__vg_in_has_comment, &ctx1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_has_comment = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_has_comment <= 1ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    vg_sax_ctx c0 = {0}, c1 = {0};
    __vg_run_world_0(__vg_in_has_comment, &c0);
    __vulgate_any_blocked = 0;
    __vg_run_world_1(__vg_in_has_comment, &c1);
    _Bool __vg_obs_diff = (c0.emitted_comment != c1.emitted_comment) || (c0.emitted_body != c1.emitted_body);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'httpd_rewrite_lookup':
        return HTTPD_ENV_MODEL + '''
char *lookup_variable(char *var, void *ctx) {
    (void)ctx;
    if (var && var[0] == 'H') return "ordinary";
    return "";
}

static int vg_do_expand_caller(uint64_t uses_var, size_t *expanded_len) {
    char vname[8] = {'H', 'T', 'T', 'P', 0};
    if (!uses_var) {
        *expanded_len = 5;
        return 1;
    }
    char *val = lookup_variable(vname, NULL);
    __CPROVER_assert(val != NULL, "vg.caller.nonnull_var_string");
    *expanded_len = (val[0] == 0) ? 0 : 8;
    return (*expanded_len > 0) ? 1 : 0;
}

int __vg_run_world_0(uint64_t uses_var, size_t *elen) { return vg_do_expand_caller(uses_var, elen); }
int __vg_run_world_1(uint64_t uses_var, size_t *elen) { return vg_do_expand_caller(uses_var, elen); }

void __vg_verify_obligations(void) {
    uint64_t __vg_in_uses_var = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_uses_var <= 1ULL);
    size_t elen1 = 0;
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    int matched1 = __vg_run_world_1(__vg_in_uses_var, &elen1);
    (void)matched1;
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_uses_var = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_uses_var <= 1ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    size_t e0 = 0, e1 = 0;
    int m0 = __vg_run_world_0(__vg_in_uses_var, &e0);
    __vulgate_any_blocked = 0;
    int m1 = __vg_run_world_1(__vg_in_uses_var, &e1);
    _Bool __vg_obs_diff = (m0 != m1) || (e0 != e1);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'php_multipart_startup':
        return _php_allocator_c() + '''
typedef struct vg_php_mp_state {
    uint8_t modules_activated;
    uint8_t throws;
    void *uploads;
    int content_type_freed;
    int parsed_fields;
} vg_php_mp_state;

static vg_php_mp_state vg_mp_globals;
uint8_t __vg_php_sym_activated = 0;
uint8_t __vg_php_sym_throws = 0;
uintptr_t __vg_php_sym_uploads = 0;

void rfc1867_post_handler(char *content_type_dup, void *arg) {
    (void)content_type_dup; (void)arg;
    vg_mp_globals.parsed_fields = 1;
}

static void vg_sapi_handle_post_episode(uint64_t is_multipart, uint64_t activated, uint64_t throws_ex, vg_php_mp_state *out) {
    memset(&vg_mp_globals, 0, sizeof(vg_mp_globals));
    vg_mp_globals.modules_activated = (uint8_t)activated;
    vg_mp_globals.throws = (uint8_t)throws_ex;
    vg_mp_globals.uploads = NULL;
    __vg_php_sym_activated = (uint8_t)activated;
    __vg_php_sym_throws = (uint8_t)throws_ex;
    __vg_php_sym_uploads = 0ULL;
    char ctype[] = "multipart/form-data";
    int arr = 0;
    if (is_multipart) {
        rfc1867_post_handler(ctype, &arr);
        vg_mp_globals.content_type_freed = 1;
    } else {
        vg_mp_globals.parsed_fields = 1;
        vg_mp_globals.content_type_freed = 1;
    }
    *out = vg_mp_globals;
}

int __vg_run_world_0(uint64_t is_mp, uint64_t act, uint64_t thr, vg_php_mp_state *out) {
    vg_sapi_handle_post_episode(is_mp, act, thr, out);
    return out->parsed_fields;
}
int __vg_run_world_1(uint64_t is_mp, uint64_t act, uint64_t thr, vg_php_mp_state *out) {
    vg_sapi_handle_post_episode(is_mp, act, thr, out);
    return out->parsed_fields;
}

void __vg_verify_obligations(void) {
    uint64_t __vg_in_is_mp = __vulgate_nondet_u64();
    uint64_t __vg_in_activated = __vulgate_nondet_u64();
    uint64_t __vg_in_throws = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_is_mp <= 1ULL && __vg_in_activated <= 1ULL && __vg_in_throws <= 1ULL);
    vg_php_mp_state st1 = {0};
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    __vg_run_world_1(__vg_in_is_mp, __vg_in_activated, __vg_in_throws, &st1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    _Bool startup_mp = (__vg_in_is_mp == 1ULL && __vg_in_activated == 0ULL && __vg_in_throws == 0ULL);
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_is_mp = __vulgate_nondet_u64();
    uint64_t __vg_in_activated = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_is_mp <= 1ULL && __vg_in_activated <= 1ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    vg_php_mp_state s0 = {0}, s1 = {0};
    __vg_run_world_0(__vg_in_is_mp, __vg_in_activated, 0ULL, &s0);
    __vulgate_any_blocked = 0;
    __vg_run_world_1(__vg_in_is_mp, __vg_in_activated, 0ULL, &s1);
    _Bool __vg_obs_diff = (s0.parsed_fields != s1.parsed_fields) || (s0.content_type_freed != s1.content_type_freed);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    if kind == 'php_session_progress':
        return _php_allocator_c() + '''
typedef struct vg_php_sess_obs {
    int upload_saved;
    int progress_created;
    int stale_global_across_requests;
} vg_php_sess_obs;

static void *vg_ps_progress_ptr = NULL;

int php_session_rfc1867_callback(unsigned int event, void *event_data, void **extra) {
    (void)event_data; (void)extra;
    static int dummy_prog = 1;
    if (event == 0) vg_ps_progress_ptr = &dummy_prog;
    return 0;
}

static void vg_two_request_worker_episode(uint64_t req_has_progress, vg_php_sess_obs *obs) {
    void *extra = NULL;
    int ev_data = 1;
    int vg_req1_left_progress;
    vg_ps_progress_ptr = NULL;
    obs->upload_saved = 0;
    obs->progress_created = 0;
    obs->stale_global_across_requests = 0;
    if (req_has_progress) {
        int cb_rc = php_session_rfc1867_callback(0U, &ev_data, &extra);
        if (cb_rc == 0) {
            obs->upload_saved = 1;
        }
        obs->progress_created = (vg_ps_progress_ptr != NULL);
    } else {
        obs->upload_saved = 1;
    }
    vg_req1_left_progress = (vg_ps_progress_ptr != NULL);
    extra = NULL;
    (void)php_session_rfc1867_callback(1U, &ev_data, &extra);
    obs->stale_global_across_requests = vg_req1_left_progress;
}

int __vg_run_world_0(uint64_t has_prog, vg_php_sess_obs *obs) { vg_two_request_worker_episode(has_prog, obs); return obs->upload_saved; }
int __vg_run_world_1(uint64_t has_prog, vg_php_sess_obs *obs) { vg_two_request_worker_episode(has_prog, obs); return obs->upload_saved; }

void __vg_verify_obligations(void) {
    uint64_t __vg_in_has_prog = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_has_prog <= 1ULL);
    vg_php_sess_obs obs1 = {0};
    __vulgate_any_blocked = 0;
    __vulgate_action_write_ok = 1;
    __vg_run_world_1(__vg_in_has_prog, &obs1);
    __CPROVER_assert(0, "vg.obligation.action_continuation_safe");
    __CPROVER_assert(0, "vg.target.violation_w1");
}

void __vg_impact_harness(void) {
    uint64_t __vg_in_has_prog = __vulgate_nondet_u64();
    __CPROVER_assume(__vg_in_has_prog <= 1ULL);
    /*VG_IMPACT_REGION_ASSUME*/
    vg_php_sess_obs o0 = {0}, o1 = {0};
    __vg_run_world_0(__vg_in_has_prog, &o0);
    __vulgate_any_blocked = 0;
    __vg_run_world_1(__vg_in_has_prog, &o1);
    _Bool __vg_obs_diff = (o0.upload_saved != o1.upload_saved) || (o0.progress_created != o1.progress_created);
    /*VG_IMPACT_QUERY_ASSERT*/
}
'''

    raise ValueError(f'unhandled cut_harness_kind: {kind}')
