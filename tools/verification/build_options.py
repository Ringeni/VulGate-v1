"""Native code-generation options retained after preprocessing.

These options are replayed into native objects, not translated into GOTO
instructions. Type layout is checked with these same options; machine-code
generation remains within the existing native-compiler trust assumption.
Options changing C expressions or object bounds need separate qualification.
"""
import re


CODEGEN_OPTIONS = {
    '-fno-common', '-fno-data-sections', '-fno-function-sections',
    '-fno-gcse', '-foptimize-sibling-calls',
    '-fomit-frame-pointer', '-fno-omit-frame-pointer',
    '-fno-stack-check', '-fno-stack-clash-protection', '-fno-stack-protector',
    '-fconserve-stack', '-fno-asynchronous-unwind-tables', '-fasynchronous-unwind-tables',
    '-fcf-protection=none',
}

# No alternate calling conventions, 16-bit boot profile or arbitrary -m flags.
X86_64_OPTIONS = {
    '-mcmodel=kernel', '-mcmodel=small', '-mno-red-zone',
    '-mno-sse', '-mno-sse2', '-mno-mmx', '-mno-3dnow', '-mno-avx',
    '-mno-80387', '-mno-fp-ret-in-387', '-mskip-rax-setup', '-mtune=generic',
    '-mpreferred-stack-boundary=3', '-mpreferred-stack-boundary=4',
}


def codegen_option(flag):
    if flag in CODEGEN_OPTIONS or flag in X86_64_OPTIONS:
        return True
    match = re.fullmatch(r'-falign-(?:functions|jumps|loops)=([0-9]+)', flag)
    if match:
        alignment = int(match[1])
        return alignment > 0 and alignment <= 65536 and alignment & (alignment - 1) == 0
    return False


def call_profile(flags):
    """Reject incompatible per-unit stack conventions before constructing a root."""
    boundary = 4  # GCC x86-64 SysV default.
    for flag in flags:
        if flag.startswith('-mpreferred-stack-boundary='):
            boundary = int(flag.split('=')[1])
    return {'x86_64_preferred_stack_boundary': boundary}
