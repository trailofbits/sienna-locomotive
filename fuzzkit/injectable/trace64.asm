PUBLIC asm_trace

EXTERN	traceSelf:		PROC

.DATA
	ret_addr	dq	0
	stdout      dd	-11
	hello		db	"Hello from ASM.",0Ah,0

.CODE

; create shadow space and align 16
sub_shadow MACRO
	mov		rbx, rsp
	and		rbx, 0Fh
	add		rbx, 20h
	sub		rsp, rbx
ENDM

; clear shadow space and alignment
add_shadow MACRO
	add		rsp, rbx
ENDM

mcall MACRO fn
	sub_shadow
	call	fn
	add_shadow
ENDM

prologue MACRO
	push	rbp
	mov		rbp, rsp
	push	rbx
ENDM

epilogue MACRO
	pop		rbx
	mov		rsp, rbp
	pop		rbp
	ret
ENDM

;; ASM ;;
; push	rax
; mov	rax, asm_trace
; call	rax

;; OPCODES (13 bytes) ;;
; 50
; 48 b8 [8 bytes addr LE (backward)]
; ff d0

; call_trace PROC
;	prologue
;	push	rax
;	mov		rax, asm_trace
;	call	rax
;	epilogue
; call_trace ENDP

; CC FF D0

asm_trace PROC
	; restore rax cause caller can't
	; [rsp - 16]	old_rax
	; [rsp - 8]		ret_addr
	pop		[ret_addr]
	pop		rax
	push	[ret_addr]
	; prologue
	push	rbp
	mov		rbp, rsp
	; save volatile registers
	pushf
	push	rax
	push	rcx
	push	rdx
	push	r8
	push	r9
	push	r10
	push	r11
	; save non-volatile registers (that we use)
	push	rbx
	; fixup ret addr
	; [rbp - 16]	ret_addr
	; [rbp - 8]		old_rbp
	sub		[ret_addr], 13	; compensate for 13 byte trampoline
	mov		rbx, [ret_addr]
	mov		[rbp - 16], rbx
	; function body
	mov		rcx, [ret_addr]
	mcall	traceSelf
	; restore non-volatile registers
	pop		rbx
	; restore volatile registers
	pop		r11
	pop		r10
	pop		r9	
	pop		r8
	pop		rdx
	pop		rcx
	pop		rax
	popf
	; epilogue
	mov		rsp, rbp
	pop		rbp
	ret
asm_trace ENDP

END