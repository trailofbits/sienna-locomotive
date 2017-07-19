section .data
    author      db 'TACIXAT',0x0a
    author_len  equ $-author
    arg_err     db 'error: invalid test number',0x0a
    arg_len     equ $-arg_err
    use_err     db 'USAGE: ./test TEST_NUMBER',0x0a
    use_len     equ $-use_err
    tmpfile     db '/tmp/crash_scratch',0x00
    tmplen      equ $-tmpfile
    null_data   db 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0  ; 16
    null_len    equ $-null_data
    aaaa_data   db "AAAAAAAAAAAAAAAA"               ; 16
    aaaa_len    equ $-aaaa_data

section .text
; global _start 
extern printf
extern open
extern malloc
extern free

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
    je      test_indirect
    cmp     rax, 1
    je      test_read_null_nt
    cmp     rax, 2
    je      test_read_null_t
    cmp     rax, 3
    je      test_read_t
    xor     rax, rax
main_finish:
    call    exit
test_indirect:
    call    indirect
    jmp     main_finish
test_read_null_nt:
    call    read_null_nt
    jmp     main_finish
test_read_null_t:
    call    read_null_t
    jmp     main_finish
test_read_t:
    call    read_t
    jmp     main_finish

global pret_test
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

global read_null_nt
read_null_nt:
;   args:   none
;   rets:   none
    xor     rax, rax
    mov     rbx, [rax]

global read_nt
read_nt:
;   args:   none
;   rets:   none
    mov     rax, 0x4141414141414141
    mov     rbx, [rax]

global read_null_t
read_null_t:
;   args:   none
;   rets:   none
    mov     rdi, tmpfile
    mov     rsi, null_data
    mov     rdx, null_len
    call    prep_test
    call    read_file_8
    ; xor     rax, rax
    mov     rbx, [rax]

global read_t
read_t:
;   args:   none
;   rets:   none
    mov     rdi, tmpfile
    mov     rsi, aaaa_data
    mov     rdx, aaaa_len
    call    prep_test
    call    read_file_8
    mov     rbx, [rax]

global read_null_nt
write_null_nt:
;   args:   none
;   rets:   none
    xor     rax, rax
    mov     [rax], rbx

write_nt:
;   args:   none
;   rets:   none
    mov     rax, 0x4141414141414141
    mov     [rax], rbx


write_null_t:
;   args:   none
;   rets:   none
    call    read_8
    xor     rax, rax
    mov     [rax], rbx

write_t:
;   args:   none
;   rets:   none
    call    read_8
    mov     [rax], rbx

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
    mov     rdx, 1
    call    write_fd
    mov     rsp, rbp
    pop     rbp
    ret    

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

write_stdin:    
;   args:   
;       rax, bytes to write
;       rcx, length
;   rets:   none
    push    rbp
    mov     rbp, rsp
    mov     rsi, rax
    mov     rdx, rcx
    mov     rdi, 0      ; stdout
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