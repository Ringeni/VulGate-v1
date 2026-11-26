#ifdef _WIN32
# define FIRST %rcx
# define FIRST_DWORD %ecx
# define SECOND %rdx
# define SECOND_DWORD %edx
#else
# define FIRST %rdi
# define FIRST_DWORD %edi
# define SECOND %rsi
# define SECOND_DWORD %esi
#endif

    .text
    .globl repair_config
repair_config:
    test FIRST_DWORD, FIRST_DWORD
    jnz 1f
    sub $192, %rsp
    movb $0xa9, 176(%rsp)
    .globl repair_config_site
repair_config_site:
    movzbl 176(%rsp), %eax
    add $192, %rsp
    ret
1:
    mov $-1, %eax
    ret

    .globl repair_regex
repair_regex:
    test SECOND_DWORD, SECOND_DWORD
    jnz 2f
    push %rbx
    mov FIRST, %rbx
    .globl repair_regex_site
repair_regex_site:
    movzbl 64(%rbx), %eax
    and $0xfb, %eax
    mov %al, 64(%rbx)
    pop %rbx
    ret
2:
    mov $-1, %eax
    ret

    .globl repair_complex
repair_complex:
    push %rbp
    push %r12
    mov FIRST, %rbp
    mov SECOND, %r12
    movb $0xa7, 64(%r12)
    movdqu 32(%rbp), %xmm0
    .globl repair_complex_site
repair_complex_site:
    movzbl 64(%r12), %eax
    movzbl 64(%rbp), %edx
    and $0xfb, %eax
    and $0x04, %edx
    or %edx, %eax
    mov %al, 64(%r12)
    movdqu %xmm0, 32(%r12)
    pop %r12
    pop %rbp
    ret

#ifdef __linux__
    .section .note.GNU-stack,"",@progbits
#endif
