.code

PUBLIC capture_ctx
capture_ctx PROC
    pushfq
    
    mov [rcx + 78h], rax
    mov [rcx + 80h], rcx
    mov [rcx + 88h], rdx
    mov [rcx + 0B8h], r8
    mov [rcx + 0C0h], r9
    mov [rcx + 0C8h], r10
    mov [rcx + 0D0h], r11
    
    mov word ptr [rcx + 38h], cs
    mov word ptr [rcx + 3Ah], ds
    mov word ptr [rcx + 3Ch], es
    mov word ptr [rcx + 42h], ss
    mov word ptr [rcx + 3Eh], fs
    mov word ptr [rcx + 40h], gs
    
    mov [rcx + 90h], rbx
    mov [rcx + 0A0h], rbp
    mov [rcx + 0A8h], rsi
    mov [rcx + 0B0h], rdi
    mov [rcx + 0D8h], r12
    mov [rcx + 0E0h], r13
    mov [rcx + 0E8h], r14
    mov [rcx + 0F0h], r15
    
    lea rax, [rsp + 10h]
    mov [rcx + 98h], rax
    
    mov rax, [rsp + 8]
    mov [rcx + 0F8h], rax
    
    mov eax, [rsp]
    mov [rcx + 44h], eax
    
    add rsp, 8
    ret
    
capture_ctx ENDP



END

