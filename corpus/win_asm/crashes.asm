; rcx, rdx, r8, r9
; regs: https://msdn.microsoft.com/en-us/library/9z1stfyw.aspx
; "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.11.25503\bin\Hostx64\x64\ml64.exe" crashes.asm /link /subsystem:windows /libpath:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.16299.0\um\x64" /defaultlib:kernel32.lib /defaultlib:user32.lib /entry:main

.DATA
  stdout      dd   -11
  paddr       dq    0
  lib         dq    0
  argc        dd    0
  ntdll       db    "ntdll.dll",0
  shdll       db    "shell32.dll",0
  c2av        db    "CommandLineToArgvW",0
  arg_err     db    "ERROR: invalid argument",0Ah
  arg_len     equ   $-arg_err
  scratch     db    "%TEMP%\crash_scratch.txt",0
  fscratch    db    512 DUP(?)
  null_data   db    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0  ; 16
  null_len    equ   $-null_data
  aaaa_data   db    "AAAAAAAAAAAAAAAA"               ; 16
  aaaa_len    equ   $-aaaa_data
  ; GEN USAGE
  use_err     db "USAGE: ./crashes.exe TEST_NUMBER",0Ah
              db '0	read_null_nt',0Ah
              db '1	read_nt',0Ah
              db '2	read_null_t',0Ah
              db '3	read_t',0Ah
              db '4	write_null_nt',0Ah
              db '5	write_nt',0Ah
              db '6	write_null_t',0Ah
              db '7	write_t',0Ah
              db '8	jump_indirect_nt',0Ah
              db '9	jump_indirect_t',0Ah
              db '10	call_indirect_nt',0Ah
              db '11	call_indirect_t',0Ah
              db '12	xor_clear_nt',0Ah
              db '13	xor_t',0Ah
              db '14	xchg_t',0Ah
              db '15	xchg_nt',0Ah
              db '16	pop_t',0Ah
              db '17	stack_ptr_ret_t',0Ah
              db '18	div_zero',0Ah
              db '19	stack_exhaustion',0Ah
              db '20	break_point',0Ah
              db '21	undefined_insn',0Ah
              db '22	stack_exec',0Ah
              db '23	use_after_free_t',0Ah
              db '24	double_free_nt',0Ah
              db '25	dep',0Ah
  use_len     equ $-use_err
  ; END USAGE

.CODE
EXTRN   GetCommandLineW:            PROC
EXTRN   ExpandEnvironmentStringsA:  PROC
EXTRN   CreateFileA:                PROC
EXTRN   WriteFile:                  PROC
EXTRN   ReadFile:                   PROC
EXTRN   CloseHandle:                PROC
EXTRN   GetStdHandle:               PROC
EXTRN   LoadLibraryA:               PROC
EXTRN   GetProcAddress:             PROC
EXTRN   FreeLibrary:                PROC
EXTRN   GetProcessHeap:             PROC
EXTRN   HeapAlloc:                  PROC
EXTRN   HeapFree:                   PROC
EXTRN   GetLastError:               PROC
EXTRN   ExitProcess:                PROC

;;;;;;;;;;;;
;  MACROS  ;
;;;;;;;;;;;;

; create shadow space and align 16
sub_shadow MACRO
  mov   rbx, rsp
  and   rbx, 0Fh
  add   rbx, 20h
  sub   rsp, rbx
ENDM

; clear shadow space and alignment
add_shadow MACRO
  add     rsp, rbx
ENDM

mcall MACRO fn
  sub_shadow
  call    fn
  add_shadow
ENDM

prologue MACRO
  push    rbp
  mov     rbp, rsp
  push    rbx
ENDM

epilogue MACRO
  pop     rbx
  mov     rsp, rbp
  pop     rbp
  ret
ENDM

;;;;;;;;;;
;  MAIN  ;
;;;;;;;;;;

; GEN MAIN
main PROC
; main function
  prologue
  mcall   parse_args
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
  je      test_xor_clear_nt
  cmp     rax, 13
  je      test_xor_t
  cmp     rax, 14
  je      test_xchg_t
  cmp     rax, 15
  je      test_xchg_nt
  cmp     rax, 16
  je      test_pop_t
  cmp     rax, 17
  je      test_stack_ptr_ret_t
  cmp     rax, 18
  je      test_div_zero
  cmp     rax, 19
  je      test_stack_exhaustion
  cmp     rax, 20
  je      test_break_point
  cmp     rax, 21
  je      test_undefined_insn
  cmp     rax, 22
  je      test_stack_exec
  cmp     rax, 23
  je      test_use_after_free_t
  cmp     rax, 24
  je      test_double_free_nt
  cmp     rax, 25
  je      test_dep
  mcall   show_usage
main_finish:
  mov     rcx, 0
  mcall   ExitProcess
test_read_null_nt:
  mcall   read_null_nt
  jmp     main_finish
test_read_nt:
  mcall   read_nt
  jmp     main_finish
test_read_null_t:
  mcall   read_null_t
  jmp     main_finish
test_read_t:
  mcall   read_t
  jmp     main_finish
test_write_null_nt:
  mcall   write_null_nt
  jmp     main_finish
test_write_nt:
  mcall   write_nt
  jmp     main_finish
test_write_null_t:
  mcall   write_null_t
  jmp     main_finish
test_write_t:
  mcall   write_t
  jmp     main_finish
test_jump_indirect_nt:
  mcall   jump_indirect_nt
  jmp     main_finish
test_jump_indirect_t:
  mcall   jump_indirect_t
  jmp     main_finish
test_call_indirect_nt:
  mcall   call_indirect_nt
  jmp     main_finish
test_call_indirect_t:
  mcall   call_indirect_t
  jmp     main_finish
test_xor_clear_nt:
  mcall   xor_clear_nt
  jmp     main_finish
test_xor_t:
  mcall   xor_t
  jmp     main_finish
test_xchg_t:
  mcall   xchg_t
  jmp     main_finish
test_xchg_nt:
  mcall   xchg_nt
  jmp     main_finish
test_pop_t:
  mcall   pop_t
  jmp     main_finish
test_stack_ptr_ret_t:
  mcall   stack_ptr_ret_t
  jmp     main_finish
test_div_zero:
  mcall   div_zero
  jmp     main_finish
test_stack_exhaustion:
  mcall   stack_exhaustion
  jmp     main_finish
test_break_point:
  mcall   break_point
  jmp     main_finish
test_undefined_insn:
  mcall   undefined_insn
  jmp     main_finish
test_stack_exec:
  mcall   stack_exec
  jmp     main_finish
test_use_after_free_t:
  mcall   use_after_free_t
  jmp     main_finish
test_double_free_nt:
  mcall   double_free_nt
  jmp     main_finish
test_dep:
  mcall   dep
  jmp     main_finish
main ENDP 
; END MAIN

;;;;;;;;;;;;;
;   TESTS   ;
;;;;;;;;;;;;;

read_null_nt PROC
  prologue
  xor     rax, rax
  mov     rbx, [rax]
  epilogue
read_null_nt ENDP

read_nt PROC
  prologue
  mov     rax, 4141414141414141h
  mov     rbx, [rax]
  epilogue
read_nt ENDP

read_null_t PROC
  prologue
  lea     rcx, null_data
  mov     rdx, null_len
  mcall   prep_test
  mcall   read_file_8
  mov     rbx, [rax]
  epilogue
read_null_t ENDP

read_t PROC
  prologue
  lea     rcx, aaaa_data
  mov     rdx, aaaa_len
  mcall   prep_test
  mcall   read_file_8
  mov     rbx, [rax]
  epilogue
read_t ENDP

write_null_nt PROC
  prologue
  xor     rax, rax
  mov     [rax], rbx
  epilogue
write_null_nt ENDP

write_nt PROC
  prologue
  mov     rax, 4141414141414141h
  mov     [rax], rbx
  epilogue
write_nt ENDP

write_null_t PROC
  prologue
  lea     rcx, null_data
  mov     rdx, null_len
  mcall   prep_test
  mcall   read_file_8
  mov     [rax], rbx
  epilogue
write_null_t ENDP

write_t PROC
  prologue
  lea     rcx, aaaa_data
  mov     rdx, aaaa_len
  mcall   prep_test
  mcall   read_file_8
  mov     [rax], rbx
  epilogue
write_t ENDP

jump_indirect_nt PROC
  prologue
  mov     rax, 4141414141414141h
  jmp     rax
  epilogue
jump_indirect_nt ENDP

jump_indirect_t PROC
  prologue
  lea     rcx, aaaa_data
  mov     rdx, aaaa_len
  mcall   prep_test
  mcall   read_file_8
  jmp     rax
  epilogue
jump_indirect_t ENDP

call_indirect_nt PROC
  prologue
  mov     rax, 4141414141414141h
  mcall   rax
  epilogue
call_indirect_nt ENDP

call_indirect_t PROC
  prologue
  lea     rcx, aaaa_data
  mov     rdx, aaaa_len
  mcall   prep_test
  mcall   read_file_8
  mcall   rax
  epilogue
call_indirect_t ENDP

xor_clear_nt PROC
  prologue
  lea     rcx, aaaa_data
  mov     rdx, aaaa_len
  mcall   prep_test
  mcall   read_file_8
  xor     rax, rax        ; this will still be tainted on a naive system
  mov     [rax], rbx
  epilogue
xor_clear_nt ENDP

xor_t PROC
  prologue
  lea     rcx, aaaa_data
  mov     rdx, aaaa_len
  mcall   prep_test
  mcall   read_file_8
  xor     rax, rsp
  mov     [rax], rbx
  epilogue
xor_t ENDP

xchg_t PROC
  prologue
  lea     rcx, aaaa_data
  mov     rdx, aaaa_len
  mcall   prep_test
  mcall   read_file_8
  mov     r8, 0
  mov     r9, 0
  xchg    rax, r8
  mov     [r8], r9
  epilogue
xchg_t ENDP

xchg_nt PROC
  prologue
  lea     rcx, aaaa_data
  mov     rdx, aaaa_len
  mcall   prep_test
  mcall   read_file_8
  mov     r8, 0
  mov     r9, 0
  xchg    rax, r8
  mov     [rax], r9
  epilogue
xchg_nt ENDP

pop_t PROC
  prologue
  lea     rcx, aaaa_data
  mov     rdx, aaaa_len
  mcall   prep_test
  mcall   read_file_8
  push    rax
  pop     rax             ; this should not taint rsp
  mov     [rax], rbx
  epilogue
pop_t ENDP

stack_ptr_ret_t PROC
  prologue
  lea     rcx, null_data
  mov     rdx, null_len
  mcall   prep_test
  mcall   read_file_8
  mov     rsp, rbp
  pop     rbp
  mov     rsp, rax
  ret
stack_ptr_ret_t ENDP

div_zero PROC
  prologue
  mov     rax, 1000
  xor     r8, r8
  div     r8
  epilogue
div_zero ENDP

stack_exhaustion PROC
  prologue
  mcall   stack_exhaustion
  epilogue
stack_exhaustion ENDP

break_point PROC
  prologue
  int     3
  epilogue
break_point ENDP

undefined_insn PROC
  prologue
  ud2                   ; undefined
  epilogue
undefined_insn ENDP

stack_exec PROC
  prologue
  push    41414141h
  mcall   rsp
  epilogue
stack_exec ENDP

use_after_free_t PROC
  prologue
  sub     rsp, 8          ; rbp+8
  lea     rcx, aaaa_data
  mov     rdx, aaaa_len
  mcall   prep_test
  mcall   read_file_8
  push    rax             ; store tainted data
  mcall   GetProcessHeap
  mov     [rbp+8], rax    ; save heap
  mov     rcx, rax
  mov     rdx, 0
  mov     r8, 8
  mcall   HeapAlloc
  mov     rcx, [rbp+8]    ; heap
  xor     rdx, rdx       
  mov     [rax], rdx      ; set value stored to 0
  push    rax             ; store address
  mov     r8, rax         ; mem
  mcall   HeapFree
  mov     rcx, [rbp+8]    ; heap
  mov     rdx, 0
  mov     r8, 8
  mcall   HeapAlloc
  pop     rdi             ; dangling pointer to old alloc
  pop     rbx             ; tainted data
  mov     [rax], rbx      ; set to AAAAAAAA
  mcall   QWORD PTR [rdi] ; call using dangling pointer
  mov     rcx, [rbp+8]
  mov     rdx, 0
  mov     r8, rax
  mcall   HeapFree
  add     rsp, 8
  epilogue
use_after_free_t ENDP

double_free_nt PROC
  prologue
  sub     rsp, 8          ; rbp+8
  mcall   GetProcessHeap
  mov     [rbp+8], rax    ; save heap
  mov     rcx, rax
  mov     rdx, 0
  mov     r8, 8
  mcall   HeapAlloc
  mov     rcx, [rbp+8]    ; heap
  xor     rdx, rdx       
  mov     [rax], rdx      ; set value stored to 0
  push    rax             ; store address
  mov     r8, rax         ; mem
  mcall   HeapFree
  mov     rcx, [rbp+8]    ; heap
  xor     rdx, rdx       
  pop     r8              ; mem
  mcall   HeapFree
  add     rsp, 8
  epilogue
double_free_nt ENDP

dep PROC
  prologue
  sub     rsp, 8          ; rbp+8
  mcall   GetProcessHeap
  mov     [rbp+8], rax    ; save heap
  mov     rcx, rax
  mov     rdx, 0
  mov     r8, 8
  mcall   HeapAlloc
  mov     rcx, 0CCCCCCCCCCCCCCCCh
  mov     [rax], rcx      ; set value stored to break point
  mcall   rax
  mov     rcx, [rbp+8]    ; heap
  xor     rdx, rdx       
  push    rax             ; store address
  mov     r8, rax         ; mem
  mcall   HeapFree
  add     rsp, 8
  epilogue
dep ENDP

;;;;;;;;;;;;;
;  UTILITY  ;
;;;;;;;;;;;;;

show_usage PROC
  prologue
  lea     rcx, [use_err]
  xor     rdx, rdx
  mov     edx, use_len
  mcall   console_write
  epilogue
show_usage ENDP

parse_args PROC
  prologue
  push    rsi
  push    rdi
  xor     rdi, rdi
  mcall   GetCommandLineW
  push    rax
  lea     rcx, shdll
  lea     rdx, c2av
  mcall   get_proc
  pop     rax
  mov     rcx, rax
  lea     rdx, argc
  mcall   [paddr]
  push    rax
  mcall   free_lib
  pop     rax
  xor     rcx, rcx
  mov     ecx, [argc]
  cmp     ecx, 2
  jl      argument_error
  mov     rsi, [rax+8]    ; argv[1]
  xor     rdi, rdi        ; total
  xor     rcx, rcx        ; count 
  xor     rbx, rbx        ; current chr
parse_loop:
  mov     bl, [rsi+rcx]   ; argv[1][0]
  cmp     bl, 0
  je      parse_args_end
  sub     rbx, 30h        ; unasciify
  cmp     rbx, 0          ; lower bound
  jl      argument_error
  cmp     rbx, 9          ; upper bound
  jg      argument_error
  imul    rdi, 10
  add     rdi, rbx
  add     rcx, 2
  jmp     parse_loop
argument_error:
  lea     rcx, [arg_err]
  mov     rdx, arg_len
  mcall   console_write
  mov     rax, -1
  epilogue
parse_args_end:
  mov     rax, rdi
  pop     rdi
  pop     rsi
  epilogue
parse_args ENDP

prep_test PROC
; rcx   BUF
; rdx   LEN
  prologue
  push    rcx
  push    rdx
  ; Expand %TEMP%\crash_scratch.txt
  lea     rcx, scratch
  lea     rdx, fscratch
  mov     r8, 512
  mcall   ExpandEnvironmentStringsA
  
  ; Open / Create File
  ; unalign
  mov     rbx, rsp
  sub     rbx, 8        
  and     rbx, 0Fh
  sub     rsp, rbx
  ; 4 args
  lea     rcx, fscratch   
  mov     rdx, 40000000h   ; GENERIC_WRITE
  xor     r8, r8
  xor     r9, r9
  ; 3 args, push reverse (ununaligns)
  push    0
  push    80h             ; FILE_ATTRIBUTES_NORMAL
  push    2               ; CREATE_ALWAYS
  ; shadow space
  sub     rsp, 20h
  call    CreateFileA
  add     rsp, 38h        ; 18h (3 args) + 20h (shadow)
  add     rsp, rbx        ; realign

  ; Write File
  pop     r8              ; len
  pop     rdx             ; buf
  push    rax             ; save handle
  ; unalign for odd number of pushed args
  mov     rbx, rsp
  sub     rbx, 8        
  and     rbx, 0Fh
  sub     rsp, rbx
  ; args
  mov     rcx, rax        ; handle
  xor     r9, r9
  push    0               ; 1 arg (ununaligns)
  sub     rsp, 20h        ; shadow 
  call    WriteFile
  add     rsp, 28h        ; shadow + arg
  add     rsp, rbx        ; realign

  ; Close File
  pop     rcx
  mcall   CloseHandle
  epilogue
prep_test ENDP

read_file_8 PROC
  prologue
  ; Open / Create File
  ; unalign
  mov     rbx, rsp
  sub     rbx, 8        
  and     rbx, 0Fh
  sub     rsp, rbx
  ; 4 args
  lea     rcx, fscratch   
  mov     rdx, 80000000h   ; GENERIC_READ
  xor     r8, r8
  xor     r9, r9
  ; 3 args, push reverse (ununaligns)
  push    0
  push    80h             ; FILE_ATTRIBUTES_NORMAL
  push    3               ; OPEN_EXISTING
  ; shadow space
  sub     rsp, 20h
  call    CreateFileA
  add     rsp, 38h        ; 18h (3 args) + 20h (shadow)
  add     rsp, rbx        ; realign

  ; Read File
  sub     rsp, 8          ; buf
  mov     rdx, rsp
  push    rax             ; save handle
  ; unalign for odd number of pushed args
  mov     rbx, rsp
  sub     rbx, 8        
  and     rbx, 0Fh
  sub     rsp, rbx
  ; args
  mov     rcx, rax        ; handle
  mov     r8, 8           ; byte count
  xor     r9, r9
  push    0               ; 1 arg (ununaligns)
  sub     rsp, 20h        ; shadow 
  call    ReadFile
  add     rsp, 28h        ; shadow + arg
  add     rsp, rbx        ; realign

  ; Close File
  pop     rcx             ; handle
  mcall   CloseHandle
  pop     rax             ; bytes read
  epilogue
read_file_8 ENDP

console_write PROC
; rcx   MSG
; rdx   LEN
  prologue
  push    rcx
  push    rdx
  xor     rcx, rcx
  mov     ecx, [stdout]
  mcall   GetStdHandle
  mov     rcx, rax
  ; Write File
  pop     r8    ; len
  pop     rdx   ; msg
  ; unalign for odd number of pushed args
  mov     rbx, rsp
  sub     rbx, 8        
  and     rbx, 0Fh
  sub     rsp, rbx
  ; args
  mov     rcx, rax        ; handle
  xor     r9, r9
  push    0               ; 1 arg (ununaligns)
  sub     rsp, 20h        ; shadow 
  call    WriteFile
  add     rsp, 28h        ; shadow + arg
  add     rsp, rbx        ; realign
  epilogue
console_write ENDP

get_proc PROC
; Wrapper for loadlib getprocaddr
; Output stored in [lib] and [paddr]
; rcx   LIBNAME
; rdx   PROCNAME
  prologue
  push    rdx
  mcall   LoadLibraryA
  mov     [lib], rax
  mov     rcx, rax
  pop     rdx
  mcall   GetProcAddress
  mov     [paddr], rax
  epilogue
get_proc ENDP

free_lib PROC
  prologue
  mov     rcx, [lib]
  mcall   FreeLibrary
  epilogue
free_lib ENDP

End