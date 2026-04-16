.intel_syntax noprefix
#include "vmctx.inc"

.text
.global SaveRegisters
SaveRegisters:
    mov     rcx + OFFSET_RAX, rax
	mov		rax, [rsp]
	mov		[rcx + OFFSET_RIP], rax
    mov     [rcx + OFFSET_RSP], rsp
    mov     [rcx + OFFSET_RBX], rbx
    mov     [rcx + OFFSET_RSI], rsi
    mov     [rcx + OFFSET_RDI], rdi
    mov     [rcx + OFFSET_RBP], rbp
    mov     [rcx + OFFSET_R12], r12
    mov     [rcx + OFFSET_R13], r13
    mov     [rcx + OFFSET_R14], r14
    mov     [rcx + OFFSET_R15], r15

    pushfq
    pop     qword ptr [rcx + OFFSET_FLAGS]
    ret


.global LoadRegisters
LoadRegisters:
    mov     rax, [rcx + OFFSET_RAX]
    mov     rbx, [rcx + OFFSET_RBX]
    mov     rsi, [rcx + OFFSET_RSI]
    mov     rdi, [rcx + OFFSET_RDI]
    mov     rbp, [rcx + OFFSET_RBP]
    mov     r12, [rcx + OFFSET_R12]
    mov     r13, [rcx + OFFSET_R13]
    mov     r14, [rcx + OFFSET_R14]
    mov     r15, [rcx + OFFSET_R15]

    push    qword ptr [rcx + OFFSET_FLAGS]
    popfq

	mov 	rsp, [rcx + OFFSET_RSP]
	jmp		qword ptr [rcx + OFFSET_RIP]
