; syscall numbers: http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

section .data
    author      db 'TACIXAT',0x0a
    author_len  equ $-author
    arg_err     db 'error: invalid test number',0x0a
    arg_len     equ $-arg_err
    ; GEN USAGE
    use_err     db 'USAGE: ./test TEST_NUMBER',0x0a
                db '0	read_null_nt',0x0a
                db '1	read_nt',0x0a
                db '2	read_null_t',0x0a
                db '3	read_t',0x0a
                db '4	write_null_nt',0x0a
                db '5	write_nt',0x0a
                db '6	write_null_t',0x0a
                db '7	write_t',0x0a
                db '8	jump_indirect_nt',0x0a
                db '9	jump_indirect_t',0x0a
                db '10	call_indirect_nt',0x0a
                db '11	call_indirect_t',0x0a
                db '12	double_free_nt',0x0a
                db '13	use_after_free_t',0x0a
                db '14	xor_clear_nt',0x0a
                db '15	xor_t',0x0a
                db '16	stack_ptr_ret_t',0x0a
                db '17	div_zero',0x0a
                db '18	stack_exhaustion',0x0a
                db '19	break_point',0x0a
                db '20	dep',0x0a
                db '21	undefined_insn',0x0a
                db '22	stack_exec',0x0a
    use_len     equ $-use_err
    ; END USAGE
    tmpfile     db '/tmp/crash_scratch',0x00
    tmplen      equ $-tmpfile
    null_data   db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0  ; 16
    null_len    equ $-null_data
    aaaa_data   db "AAAAAAAAAAAAAAAA"               ; 16
    aaaa_len    equ $-aaaa_data

section .text
extern malloc
extern free

; GEN MAIN
global main
main:
;   args:
;       rdi, argc
;       rsi, argv
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rcx, rdi
    mov     rax, rsi
    call    parse_args
    cmp     rax, 0
    je      test_read_null_nt
    cmp     rax, 1
    je      test_read_nt
    cmp     rax, 2
    je      test_read_null_t
    cmp     rax, 3
    je      test_read_t
    cmp     rax, 4
    je      test_write_null_nt
    cmp     rax, 5
    je      test_write_nt
    cmp     rax, 6
    je      test_write_null_t
    cmp     rax, 7
    je      test_write_t
    cmp     rax, 8
    je      test_jump_indirect_nt
    cmp     rax, 9
    je      test_jump_indirect_t
    cmp     rax, 10
    je      test_call_indirect_nt
    cmp     rax, 11
    je      test_call_indirect_t
    cmp     rax, 12
    je      test_double_free_nt
    cmp     rax, 13
    je      test_use_after_free_t
    cmp     rax, 14
    je      test_xor_clear_nt
    cmp     rax, 15
    je      test_xor_t
    cmp     rax, 16
    je      test_stack_ptr_ret_t
    cmp     rax, 17
    je      test_div_zero
    cmp     rax, 18
    je      test_stack_exhaustion
    cmp     rax, 19
    je      test_break_point
    cmp     rax, 20
    je      test_dep
    cmp     rax, 21
    je      test_undefined_insn
    cmp     rax, 22
    je      test_stack_exec
    xor     rax, rax
    call    show_usage
main_finish:
    mov     rax, 2
    call    exit
test_read_null_nt:
    call    read_null_nt
    jmp     main_finish
test_read_nt:
    call    read_nt
    jmp     main_finish
test_read_null_t:
    call    read_null_t
    jmp     main_finish
test_read_t:
    call    read_t
    jmp     main_finish
test_write_null_nt:
    call    write_null_nt
    jmp     main_finish
test_write_nt:
    call    write_nt
    jmp     main_finish
test_write_null_t:
    call    write_null_t
    jmp     main_finish
test_write_t:
    call    write_t
    jmp     main_finish
test_jump_indirect_nt:
    call    jump_indirect_nt
    jmp     main_finish
test_jump_indirect_t:
    call    jump_indirect_t
    jmp     main_finish
test_call_indirect_nt:
    call    call_indirect_nt
    jmp     main_finish
test_call_indirect_t:
    call    call_indirect_t
    jmp     main_finish
test_double_free_nt:
    call    double_free_nt
    jmp     main_finish
test_use_after_free_t:
    call    use_after_free_t
    jmp     main_finish
test_xor_clear_nt:
    call    xor_clear_nt
    jmp     main_finish
test_xor_t:
    call    xor_t
    jmp     main_finish
test_stack_ptr_ret_t:
    call    stack_ptr_ret_t
    jmp     main_finish
test_div_zero:
    call    div_zero
    jmp     main_finish
test_stack_exhaustion:
    call    stack_exhaustion
    jmp     main_finish
test_break_point:
    call    break_point
    jmp     main_finish
test_dep:
    call    dep
    jmp     main_finish
test_undefined_insn:
    call    undefined_insn
    jmp     main_finish
test_stack_exec:
    call    stack_exec
    jmp     main_finish
; END MAIN

;;;;;;;;;;;;;
;   TESTS   ;
;;;;;;;;;;;;;

global read_null_nt
read_null_nt:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    xor     rax, rax
    mov     rbx, [rax]
    mov     rsp, rbp
    pop     rbp
    ret

global read_nt
read_nt:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rax, 0x4141414141414141
    mov     rbx, [rax]
    mov     rsp, rbp
    pop     rbp
    ret

global read_null_t
read_null_t:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rdi, tmpfile
    mov     rsi, null_data
    mov     rdx, null_len
    call    prep_test
    call    read_file_8
    mov     rbx, [rax]
    mov     rsp, rbp
    pop     rbp
    ret

global read_t
read_t:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rdi, tmpfile
    mov     rsi, aaaa_data
    mov     rdx, aaaa_len
    call    prep_test
    call    read_file_8
    mov     rbx, [rax]
    mov     rsp, rbp
    pop     rbp
    ret

global write_null_nt
write_null_nt:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    xor     rax, rax
    mov     [rax], rbx
    mov     rsp, rbp
    pop     rbp
    ret

global write_nt
write_nt:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rax, 0x4141414141414141
    mov     [rax], rbx
    mov     rsp, rbp
    pop     rbp
    ret

global write_null_t
write_null_t:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rdi, tmpfile
    mov     rsi, null_data
    mov     rdx, null_len
    call    prep_test
    call    read_file_8
    mov     [rax], rbx
    mov     rsp, rbp
    pop     rbp
    ret

global write_t
write_t:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rdi, tmpfile
    mov     rsi, aaaa_data
    mov     rdx, aaaa_len
    call    prep_test
    call    read_file_8
    mov     [rax], rbx
    mov     rsp, rbp
    pop     rbp
    ret

global jump_indirect_nt
jump_indirect_nt:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rax, 0x4141414141414141
    jmp     rax
    mov     rsp, rbp
    pop     rbp
    ret

global jump_indirect_t
jump_indirect_t:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rsi, aaaa_data
    mov     rdx, aaaa_len
    call    prep_test
    call    read_file_8
    jmp     rax
    mov     rsp, rbp
    pop     rbp
    ret

global call_indirect_nt
call_indirect_nt:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rax, 0x4141414141414141
    call    rax
    mov     rsp, rbp
    pop     rbp
    ret

global call_indirect_t
call_indirect_t:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rsi, aaaa_data
    mov     rdx, aaaa_len
    call    prep_test
    call    read_file_8
    call    rax
    mov     rsp, rbp
    pop     rbp
    ret

global double_free_nt
double_free_nt:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    push    rbp
    mov     rbp, rsp
    mov     rsi, aaaa_data
    mov     rdx, aaaa_len
    call    prep_test
    call    read_file_8
    push    rax
    mov     rdi, 8
    call    malloc
    pop     rbx
    mov     [rax], rbx
    push    rax
    mov     rdi, rax
    call    free
    pop     rdi
    call    free
    mov     rsp, rbp
    pop     rbp
    ret

global use_after_free_t
use_after_free_t:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    push    rbp
    mov     rbp, rsp
    mov     rsi, aaaa_data
    mov     rdx, aaaa_len
    call    prep_test
    call    read_file_8
    push    rax
    mov     rdi, 8
    call    malloc
    pop     rbx
    mov     [rax], rbx
    push    rax
    mov     rdi, rax
    call    free
    pop     rdi
    mov     rax, [rdi]
    mov     rsp, rbp
    pop     rbp
    ret

global xor_clear_nt
xor_clear_nt:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rdi, tmpfile
    mov     rsi, aaaa_data
    mov     rdx, aaaa_len
    call    prep_test
    call    read_file_8
    xor     rax, rax        ; this will still be tainted on a naive system
    mov     [rax], rbx
    mov     rsp, rbp
    pop     rbp
    ret

global xor_t
xor_t:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rdi, tmpfile
    mov     rsi, aaaa_data
    mov     rdx, aaaa_len
    call    prep_test
    call    read_file_8
    xor     rax, rsp
    mov     [rax], rbx
    mov     rsp, rbp
    pop     rbp
    ret

global stack_ptr_ret_t
stack_ptr_ret_t:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rdi, tmpfile
    mov     rsi, null_data
    mov     rdx, null_len
    call    prep_test
    call    read_file_8
    mov     rsp, rbp
    pop     rbp
    mov     rsp, rax
    ret

global div_zero
div_zero:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rax, 1000
    xor     r8, r8
    div     r8
    mov     rsp, rbp
    pop     rbp
    ret

global stack_exhaustion
stack_exhaustion:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    call    stack_exhaustion
    mov     rsp, rbp
    pop     rbp
    ret

global break_point
break_point:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    int     3
    mov     rsp, rbp
    pop     rbp
    ret

global dep
dep:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rax, 135    ; get persona
    mov     rdi, -1
    syscall
    mov     rdi, rax
    mov     rbx, 0x0400000
    not     rbx
    and     rdi, rbx    ; remove READ_IMPLIES_EXEC
    mov     rax, 135    ; set persona
    syscall
    mov     rax, 9
    xor     rdi, rdi    ; addr
    mov     rsi, 4096   ; size
    mov     rdx, 3      ; read | write
    mov     r10, 0x22   ; anon | private
    mov     r8, -1      ; fd
    xor     r9, r9
    syscall
    mov     rbx, 0xcc
    mov     [rax], rbx
    call    rax
    mov     rsp, rbp
    pop     rbp
    ret

global undefined_insn
undefined_insn:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    ud2                 ; undefined
    mov     rsp, rbp
    pop     rbp
    ret

global stack_exec
stack_exec:
;   args:   none
;   rets:   none
    push    rbp
    mov     rbp, rsp
    push    0x41414141
    call    rsp
    mov     rsp, rbp
    pop     rbp
    ret

; global template
; template:
; ;   args:   none
; ;   rets:   none
;     push    rbp
;     mov     rbp, rsp

;     mov     rsp, rbp
;     pop     rbp
;     ret

;;;;;;;;;;;;;;;;;;;;;;;;;
;   UTILITY FUNCTIONS   ;
;;;;;;;;;;;;;;;;;;;;;;;;;

global parse_args
parse_args:
;   args:
;       rcx, argc
;       rax, argv
;   rets:   rax, test number
    push    rbp
    mov     rbp, rsp
    cmp     rcx, 2
    jl      invalid_use
    mov     rsi, [rax+8]    ; argv[1]
    xor     rdi, rdi        ; total
    xor     rcx, rcx        ; count
    xor     rbx, rbx        ; current chr
parse_loop:
    mov     bl, [rsi+rcx]   ; argv[1][0]
    cmp     bl, 0
    je      parse_args_finish
    sub     rbx, 0x30       ; unasciify
    cmp     rbx, 0          ; lower bound
    jl      invalid_arg
    cmp     rbx, 9          ; upper bound
    jg      invalid_arg
    imul    rdi, 10
    add     rdi, rbx
    inc     rcx
    jmp     parse_loop
parse_args_finish:
    mov     rax, rdi        ; ret    
    mov     rsp, rbp
    pop     rbp
    ret
invalid_use:
    call    show_usage
    mov     rax, 1
    call    exit
invalid_arg:
    mov     rax, arg_err
    mov     rcx, arg_len
    call    write
    mov     rax, 1
    call    exit

global prep_test
prep_test:
;   args:   
;       rdi, filename
;       rsi, data to write
;       rdx, data length
;   rets:
;       none
    push    rbp
    mov     rbp, rsp
    push    rsi
    push    rdx
    mov     rax, 2          ; open
    mov     rdi, tmpfile    ; file
    mov     rsi, 1102o      ; O_CREAT | O_TRUNC | O_WRONLY
    mov     rdx, 664o       ; persimmons
    syscall
    pop     rdx             ; data len
    pop     rdi             ; data
    push    rax             ; fd
    mov     rax, rdi
    mov     rcx, rdx
    pop     rdx
    push    rdx             ; fd
    call    write_fd
    pop     rdi             ; fd
    mov     rax, 3
    syscall
    mov     rsp, rbp
    pop     rbp
    ret

global show_usage
show_usage:
    push    rbp
    mov     rbp, rsp
    mov     rax, use_err
    mov     rcx, use_len
    call    write
    mov     rsp, rbp
    pop     rbp
    ret    

global read_file_8
read_file_8:
;   args:   none
;   rets:   rax, 8 bytes read
    push    rbp
    mov     rbp, rsp
    ; open
    mov     rax, 2          ; open
    mov     rdi, tmpfile    ; file
    mov     rsi, 0          ; O_RDONLY
    mov     rdx, 0          ; persimmons
    syscall
    push    rax             ; fd
    ; read
    mov     rdi, rax        ; fd
    xor     rax, rax        ; read
    sub     rsp, 8          
    mov     rsi, rsp        ; buf
    mov     rdx, 8          ; size
    syscall
    pop     rax             ; data
    ; close
    pop     rdi             ; fd
    push    rax
    mov     rax, 3          ; close
    syscall
    pop     rax
    mov     rsp, rbp
    pop     rbp
    ret

global read_8
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

global write_8
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

global write
write:
;   args:   
;       rax, bytes to write
;       rcx, length
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rdx, 1
    call    write_fd
    mov     rsp, rbp
    pop     rbp
    ret    

global write_fd
write_fd:
;   args:   
;       rax, bytes to write
;       rcx, length
;       rdx, fd
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rdi, rdx    ; fd
    mov     rsi, rax    ; buf
    mov     rdx, rcx    ; count
    mov     rax, 1      ; write
    syscall
    mov     rsp, rbp
    pop     rbp
    ret    

global exit
exit:
;   args:   rax, exit code
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rdi, rax    ; code
    mov     rax, 0x3c   ; exit
    syscall