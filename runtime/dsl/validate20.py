"""Synthetic fixtures used by the DSL→VM validation and benchmarks.

For each DSL case we build a tiny executable that exports the target symbol and
counts body executions.  The VM is installed by vm_validate/vm_bench; a BLOCK
must keep body_calls at zero.  Selector values are injected as compile-time
overrides, so complex application memory layouts are not needed.
"""
from __future__ import annotations

from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime.dsl import parser as dsl_parser  # noqa: E402

C_TYPES = {
    'int': 'int', 'uint': 'unsigned int', 'int64': 'int64_t', 'uint64': 'uint64_t',
    'pointer': 'void *', 'float': 'float', 'double': 'double', 'void': 'void',
}

TEST_VALUES = {
    'CVE-2026-109618': {'activated': 0, 'throws': 0, 'uploads': 0},
    'CVE-2026-111497': {'remaining': 0, 'sample_present': 0, 'occupied': 0,
                        'capacity': 8, 'next_in': 0, 'last_in': 0, 'available_in': 0},
    'CVE-2026-15176': {'alias': 1, 'flags': 8},
    'CVE-2026-47360': {'previous': 1},
    'CVE-2026-60005': {'captures': 1, 'flags': 32},
    'CVE-2026-97205': {'counter': 250},
}

# Scalar arguments for fixtures when the DSL condition reads the argument
# directly (memory-mode smoke test); defaults to all zeros.
SCALAR_ARGS = {}

MEMORY_MODE = {'CVE-2026-109618', 'CVE-2026-47360'}

FIXTURE_DECLS = {
    'CVE-2026-109618': '''
__attribute__((used, visibility("default"))) unsigned char core_globals[1024];
__attribute__((used, visibility("default"))) unsigned char sapi_globals[1024];
''',
    'CVE-2026-47360': '''
static unsigned char request_rec_buffer[4096];
''',
}
FIXTURE_SETUP = {
    'CVE-2026-109618': '''
    memset(core_globals, 0, sizeof(core_globals));
    memset(sapi_globals, 0, sizeof(sapi_globals));
''',
    'CVE-2026-47360': '''
    memset(request_rec_buffer, 0, sizeof(request_rec_buffer));
    *(void **)(request_rec_buffer + 32) = (void *)1;
''',
}
POINTER_ARGS = {
    'CVE-2026-47360': {0: 'request_rec_buffer'},
}

# Second scenario: selector values that make the condition false (PASS).
PASS_VALUES = {
    'CVE-2026-109618': {'activated': 1, 'throws': 0, 'uploads': 0},
    'CVE-2026-15176': {'alias': 0, 'flags': 0},
    'CVE-2026-47360': {'previous': 0},
    'CVE-2026-60005': {'captures': 0, 'flags': 0},
    'CVE-2026-97205': {'counter': 0},
}


def _selector_names(patch: dsl_parser.PatchSpec) -> set[str]:
    import re
    names = set()
    for mount in patch.mounts:
        names.update(re.findall(r'value\["([^"]+)"\]', mount.body))
    return names


def render_fixture(patch: dsl_parser.PatchSpec, case_id: str) -> str:
    calls = []
    for mount in patch.mounts:
        return_type = C_TYPES.get(mount.return_type, mount.return_type)
        args = ', '.join(f'{C_TYPES.get(kind, kind)} a{index}'
                         for index, kind in enumerate(mount.args)) or 'void'
        body = '    body_calls++;\n' + ('    return 0;' if return_type != 'void' else '    return;')
        calls.append(f'{return_type} {mount.symbol}({args})\n{{\n{body}\n}}')
    main_calls = []
    for mount in patch.mounts:
        arguments = []
        for index, kind in enumerate(mount.args):
            key = f'arg{index}'
            value = SCALAR_ARGS.get(case_id, {}).get(key)
            if kind == 'pointer':
                arguments.append(POINTER_ARGS.get(case_id, {}).get(index, '(void *)0'))
            elif value is not None:
                arguments.append(str(value))
            else:
                arguments.append('0')
        expression = f'{mount.symbol}({", ".join(arguments)})'
        if mount.return_type == 'void':
            main_calls.append(f'    {expression};')
            main_calls.append('    results[result_count++] = -999999;')
        else:
            main_calls.append(f'    results[result_count++] = (long long){expression};')
    extras = FIXTURE_DECLS.get(case_id, '')
    setup = FIXTURE_SETUP.get(case_id, '')
    return f'''#include <stdint.h>
#include <stdio.h>
#include <string.h>

static unsigned long long body_calls = 0;
{extras}
{chr(10).join(calls)}

int main(void)
{{
    char line[64];
    long long results[32];
    int result_count = 0;
{setup}
    printf("{{\\"ready\\":true}}\\n");
    fflush(stdout);
    if (fgets(line, sizeof(line), stdin) == NULL) {{
        return 2;
    }}
{chr(10).join(main_calls)}
    printf("{{\\"body_calls\\":%llu,\\"results\\":[", body_calls);
    for (int index = 0; index < result_count; index++) {{
        if (index) printf(",");
        printf("%lld", results[index]);
    }}
    printf("]}}\\n");
    fflush(stdout);
    return 0;
}}
'''


def build_fixture(patch: dsl_parser.PatchSpec, case_id: str, output: Path, cc: str = 'cc') -> Path:
    source = output.with_suffix('.c')
    source.write_text(render_fixture(patch, case_id), encoding='utf-8')
    subprocess.run([cc, '-O0', '-g', '-rdynamic', str(source), '-o', str(output)], check=True)
    return output
