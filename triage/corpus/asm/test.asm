bits 64

section .text
global _start 

_start:
    pop     rcx
    mov     rax, rsp
    call    main

main:
;   args:
;       rcx, argc
;       rax, argv
;   rets:   none
    push    rbp
    mov     rbp, rsp
    push    rcx
    push    rax
    call    parse_args
    cmp     rax, 0
    je      indirect_test
    call    read_8
    call    write_8
    xor     rax, rax
    call    indirect
finish:
    call    exit
indirect_test:
    call    indirect
    jmp     finish

parse_args:
;   args:
;       rcx, argc
;       rax, argv
;   rets:   rax, test number
    push    rbp
    mov     rbp, rsp
    cmp     rcx, 2
    jl      invalid_use
    mov     rax, [rax+8]    ; argv[1]
    xor     rbx, rbx
    mov     bl, [rax]       ; argv[1][0]
    sub     rbx, 0x30       ; unasciify
    cmp     rbx, 0          ; lower bound
    jl      invalid_arg
    cmp     rbx, 0          ; upper bound
    jg      invalid_arg
    mov     rax, rbx        ; return
    mov     rsp, rbp
    pop     rbp
    ret
invalid_use:
    mov     rax, use_err
    mov     rcx, use_len
    call    write
    mov     rax, 1
    call    exit
invalid_arg:
    mov     rax, arg_err
    mov     rcx, arg_len
    call    write
    mov     rax, 1
    call    exit

indirect:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    lea     rcx, [rel exit]
    jmp     rcx

read_8:     
;   args:   none
;   rets:   rax, 8 bytes read in
    push    rbp
    mov     rbp, rsp
    sub     rsp, 8
    mov     rax, 0      ; read
    mov     rdi, 0      ; stdin
    mov     rsi, rsp
    mov     rdx, 8
    syscall
    pop     rax
    mov     rsp, rbp
    pop     rbp
    ret

write_8:    
;   args:   rax, 8 bytes to write
;   rets:   none
    push    rbp
    mov     rbp, rsp
    push    rax
    mov     rax, rsp
    mov     rcx, 8
    call    write
    mov     rsp, rbp
    pop     rbp
    ret    

write:    
;   args:   
;       rax, bytes to write
;       rcx, length
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rsi, rax
    mov     rdx, rcx
    mov     rdi, 1      ; stdout
    mov     rax, 1      ; write
    syscall
    mov     rsp, rbp
    pop     rbp
    ret    

exit:
;   args:   rax, exit code
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rdi, rax    ; code
    mov     rax, 0x3c   ; exit
    syscall

section .data
    author      db 'TACIXAT',0x0a
    author_len  equ $-author
    arg_err     db 'error: invalid test number',0x0a
    arg_len     equ $-arg_err
    use_err     db 'USAGE: ./test TEST_NUMBER',0x0a
    use_len     equ $-use_err