.CODE

PUBLIC get_gdt_base

get_gdt_base PROC
local gdtr[10]:byte
sgdt gdtr

mov rax, qword ptr gdtr[2]

ret

get_gdt_base ENDP

PUBLIC get_cs
get_cs PROC
mov rax, cs
ret
get_cs ENDP

PUBLIC get_ds
get_ds PROC
mov rax, ds
ret
get_ds ENDP

PUBLIC get_es
get_es PROC
mov rax, es
ret
get_es endp

PUBLIC get_ss
get_ss PROC
mov rax, ss
ret
get_ss endp

PUBLIC get_gs
get_gs PROC
mov rax, gs
ret
get_gs ENDP

PUBLIC get_ldtr
get_ldtr PROC
sldt rax
ret
get_ldtr ENDP

PUBLIC get_tr
get_tr PROC
str rax
ret
get_tr ENDP

PUBLIC get_idt_base
get_idt_base PROC
local idtr[10]:byte

sidt idtr
mov rax, QWORD PTR idtr[2]
ret

get_idt_base ENDP

PUBLIC get_gdt_limit
get_gdt_limit PROC
local gdtr[10]:byte
sgdt gdtr
mov ax, word ptr gdtr[0]
ret
get_gdt_limit ENDP


PUBLIC get_idt_limit
get_idt_limit PROC

	local	idtr[10]:byte
	
	sidt	idtr
	mov		ax, word ptr idtr[0]

	ret

get_idt_limit ENDP



PUBLIC get_rflags
get_rflags PROC

	PUSHFQ
	POP		RAX
	RET

get_rflags ENDP


PUBLIC get_fs
get_fs PROC
mov rax, fs
ret
get_fs ENDP

PUBLIC capture_context
capture_context PROC

mov rax, rsp
ret
    
capture_context ENDP


.DATA
PUBLIC g_stackpointer
PUBLIC g_basepointer

g_stackpointer QWORD 0
g_basepointer QWORD 0

save_state_vmxoff PROC PUBLIC

	MOV g_stackpointer, RSP
	MOV g_basepointer, RBP

	RET

save_state_vmxoff ENDP 


vmx_off_restore_state PROC PUBLIC

	VMXOFF  
	
	MOV RSP, g_stackpointer
	MOV RBP, g_basepointer
	
	ADD RSP, 8
	
	XOR RAX, RAX
	MOV RAX, 1
	
	
	MOV     RBX, [RSP+28h+8h]
	MOV     RSI, [RSP+28h+10h]
	ADD     RSP, 020h
	POP     RDI
	
	RET
	
vmx_off_restore_state ENDP 

asm_sgdt PROC
    sgdt [rcx]
    ret
asm_sgdt ENDP

asm_sidt PROC
    sidt [rcx]
    ret
asm_sidt ENDP


END

