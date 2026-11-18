"""Differential C type checks against the native compiler, without app models."""
import json
import os

import pytest

from tools.verification.toolchain import Toolchain


@pytest.fixture
def toolchain():
    config = os.environ.get('VULGATE_C_FRONTEND_TOOLCHAIN')
    if not config:
        pytest.skip('set VULGATE_C_FRONTEND_TOOLCHAIN for the qualified C frontend')
    return Toolchain.load(config)


EXPRESSIONS = {
    'literal': '0', 'arithmetic': '(2-2)', 'enum': 'zero',
    'parameter': 'n', 'multiply_zero': '(n*0)', 'self_subtract': '(n-n)',
    'local_const': 'k', 'static_const': 'global_k',
    'sizeof_fixed': '(sizeof(int)-sizeof(int))',
    'sizeof_vla': '(sizeof(int[n])-sizeof(int[n]))',
    'short_and': '(0 && n)', 'short_or': '(1 || n)-1',
    'conditional_runtime_arm': '(1 ? 0 : n)',
    'conditional_bad_arm': '(1 ? 0 : 1/0)',
    'float_immediate_cast': '(int)0.0',
    'float_arithmetic_cast': '(int)(0.5-0.5)',
    'float_compare': '(0.0 != 0.0)',
    'pointer_roundtrip': '(long)(void*)0', 'comma': '(0,0)',
    'shift_zero': '((1 << 4) >> 5)', 'bitwise_zero': '(5 & ~5)',
}


def run(toolchain, command, args, directory, *, external=False):
    method = toolchain.run_external if external else toolchain.run
    result = method(command, args, 90, cwd=directory)
    assert not result.timed_out, result.to_dict()
    return result


@pytest.mark.parametrize('reverse', [False, True])
@pytest.mark.parametrize('optimization', ['-O0', '-O2'])
def test_null_pointer_constant_type_matches_gcc(toolchain, tmp_path, reverse, optimization):
    declarations = ['static const int global_k=0; enum {zero=0};']
    for name, value in EXPRESSIONS.items():
        operand = f'(void *)(long)({value})'
        conditional = f'1 ? (int *)0 : {operand}' if reverse else f'1 ? {operand} : (int *)0'
        declarations.append(f'static unsigned observe_{name}(int n) {{ const int k=0; '
                            f'return sizeof(*({conditional})); }}')
    for name, operand in [('const_void', '(const void *)0'), ('volatile_void', '(volatile void *)0'),
                          ('nested_void', '(void *)(void *)0'), ('typed_pointer', '(void *)(int *)0')]:
        conditional = f'1 ? (int *)0 : {operand}' if reverse else f'1 ? {operand} : (int *)0'
        declarations.append(f'static unsigned observe_{name}(int n) {{ return sizeof(*({conditional})); }}')
    names = [*EXPRESSIONS, 'const_void', 'volatile_void', 'nested_void', 'typed_pointer']
    native_source = tmp_path / 'native.c'
    native_source.write_text('#include <stdio.h>\n' + '\n'.join(declarations) + '\nint main(void) {\n' +
                             '\n'.join(f'printf("%u\\n", observe_{name}(3));' for name in names) +
                             '\nreturn 0;}\n', encoding='utf-8')
    executable = tmp_path / 'native'
    compiled = run(toolchain, 'gcc', ['-std=gnu11', optimization, native_source, '-o', executable],
                   tmp_path, external=True)
    assert compiled.returncode == 0, compiled.to_dict()
    executed = run(toolchain, toolchain.path(executable), [], tmp_path, external=True)
    assert executed.returncode == 0, executed.to_dict()
    values = [int(line) for line in executed.stdout.splitlines()]
    assert len(values) == len(names)
    source = tmp_path / 'symbolic.c'
    source.write_text('extern void __CPROVER_assert(_Bool,const char*);\n' + '\n'.join(declarations) +
                      '\nint main(void) {\n' + '\n'.join(
                          f'__CPROVER_assert(observe_{name}(3)=={value}, "{name}");'
                          for name, value in zip(names, values)) + '\nreturn 0;}\n', encoding='utf-8')
    binary = tmp_path / 'program.goto'
    compiled = run(toolchain, 'goto-cc', ['-std=gnu11', source, '-o', binary], tmp_path)
    assert compiled.returncode == 0, compiled.to_dict()
    queried = run(toolchain, 'cbmc', [binary, '--json-ui'], tmp_path)
    (tmp_path / 'query.json').write_text(queried.stdout, encoding='utf-8')
    results = [p for item in json.loads(queried.stdout) for p in item.get('result', [])]
    assert queried.returncode == 0, [p for p in results if p['status'] != 'SUCCESS']
    assert {p['description'] for p in results if p['description'] in names} == set(names)


def test_kernel_constexpr_macro_preserves_nonconstant_argument(toolchain, tmp_path):
    source = tmp_path / 'macro.c'
    source.write_text('''
extern void __CPROVER_assert(_Bool,const char*);
#define CONSTEXPR(x) (sizeof(int) == sizeof(*(8 ? ((void *)((long)(x) * 0L)) : (int *)8)))
#define CHECK(h,l) ((int)sizeof(struct { int:(-!!(__builtin_choose_expr(CONSTEXPR((l)>(h)), (l)>(h), 0))); }))
static unsigned mask(unsigned h, unsigned l) {
    return CHECK(h,l) + ((~0U << l) & (~0U >> (31-h)));
}
int main(void) {
    __CPROVER_assert(mask(7,4)==240U,"runtime_range_typecheck");
    __CPROVER_assert(CONSTEXPR(17),"literal_is_constant");
    return 0;
}
''', encoding='utf-8')
    native = run(toolchain, 'gcc', ['-std=gnu11', '-fsyntax-only', source], tmp_path, external=True)
    assert native.returncode == 0, native.to_dict()
    binary = tmp_path / 'macro.goto'
    compiled = run(toolchain, 'goto-cc', ['-std=gnu11', source, '-o', binary], tmp_path)
    assert compiled.returncode == 0, compiled.to_dict()
    result = run(toolchain, 'cbmc', [binary, '--json-ui'], tmp_path)
    assert result.returncode == 0, result.to_dict()


@pytest.mark.parametrize('optimization', ['-O0', '-O2'])
def test_generic_selection_preserves_nested_qualifiers(toolchain, tmp_path, optimization):
    preamble = '''
struct S { int field; };
typedef int scalar;
static int fn(void) { return 0; }
#define PTR_KIND(p) _Generic((p), int*:1, const int*:2, volatile int*:3, const volatile int*:4, default:0)
#define STRUCT_KIND(p) _Generic((p), struct S*:1, const struct S*:2, volatile struct S*:3, default:0)
#define CONST_PTR(p) _Generic((p), const __typeof__(*(p))*:1, default:0)
'''
    locals_ = '''
int n=0, a[2]={0}; const int c=0, ca[2]={0}; volatile int v=0, va[2]={0}; const volatile int cv=0;
typedef int array_type[2]; const array_type ta={0};
int *p=&n; int *const cp=&n; const int *pc=&c;
struct S s={0}; const struct S cs={0}; volatile struct S vs={0};
'''
    expressions = ['PTR_KIND(&n)', 'PTR_KIND(&c)', 'PTR_KIND(&v)', 'PTR_KIND(&cv)',
                   'PTR_KIND(p)', 'PTR_KIND(cp)', 'PTR_KIND(pc)', 'PTR_KIND(a)',
                   'PTR_KIND(ca)', 'PTR_KIND(va)', 'PTR_KIND(ta)',
                   'STRUCT_KIND(&s)', 'STRUCT_KIND(&cs)', 'STRUCT_KIND(&vs)',
                   'CONST_PTR(&n)', 'CONST_PTR(&c)', 'CONST_PTR(&s)', 'CONST_PTR(&cs)',
                   '_Generic(c, const int:2, int:1, default:0)',
                   '_Generic(c, int:1, const int:2, default:0)',
                   '_Generic((scalar)0, int:1, default:0)',
                   '_Generic(fn, int(*)(void):1, default:0)',
                   '_Generic(n++, int:1, default:0)', 'n']
    native = tmp_path / 'native.c'
    native.write_text('#include <stdio.h>\n'+preamble+'\nint main(void) {\n'+locals_+
                       '\n'.join(f'printf("%d\\n", {e});' for e in expressions)+'\nreturn 0;}\n', encoding='utf-8')
    executable = tmp_path / 'native'
    compiled = run(toolchain, 'gcc', ['-std=gnu11', optimization, native, '-o', executable], tmp_path, external=True)
    assert compiled.returncode == 0, compiled.to_dict()
    executed = run(toolchain, toolchain.path(executable), [], tmp_path, external=True)
    assert executed.returncode == 0, executed.to_dict()
    values = [int(line) for line in executed.stdout.splitlines()]
    assert len(values) == len(expressions) and values[-1] == 0
    symbolic = tmp_path / 'symbolic.c'
    symbolic.write_text('extern void __CPROVER_assert(_Bool,const char*);\n'+preamble+
                         '\nint main(void) {\n'+locals_+'\n'.join(
                             f'__CPROVER_assert(({e})=={v}, "generic_{i}");'
                             for i,(e,v) in enumerate(zip(expressions,values)))+'\nreturn 0;}\n', encoding='utf-8')
    binary = tmp_path / 'generic.goto'
    compiled = run(toolchain, 'goto-cc', ['-std=gnu11', symbolic, '-o', binary], tmp_path)
    assert compiled.returncode == 0, compiled.to_dict()
    queried = run(toolchain, 'cbmc', [binary, '--json-ui'], tmp_path)
    (tmp_path / 'query.json').write_text(queried.stdout, encoding='utf-8')
    assert queried.returncode == 0, queried.to_dict()


@pytest.mark.parametrize('qualifier,expected_success', [('', True), ('const ', False)])
def test_container_accessor_keeps_mutability(toolchain, tmp_path, qualifier, expected_success):
    source = tmp_path / 'accessor.c'
    source.write_text('''
struct Inner { int n; };
struct Outer { struct Inner inner; int count; };
#define OUTER(p) _Generic((p), const __typeof__(*(p))*: ((const struct Outer *)(p)), default: ((struct Outer *)(p)))
void update(QUALIFIERstruct Inner *p) { OUTER(p)->count++; }
'''.replace('QUALIFIER', qualifier), encoding='utf-8')
    native = run(toolchain, 'gcc', ['-std=gnu11', '-fsyntax-only', source], tmp_path, external=True)
    compiled = run(toolchain, 'goto-cc', ['-std=gnu11', '-c', source, '-o', tmp_path/'accessor.goto'], tmp_path)
    assert (native.returncode == 0) == expected_success, native.to_dict()
    assert (compiled.returncode == 0) == expected_success, compiled.to_dict()
