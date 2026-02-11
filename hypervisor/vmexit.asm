.code

EXTERN RtlCaptureContext:PROC
EXTERN vmentry_handler_cpp:PROC

PUBLIC vmexit_handler
vmexit_handler PROC

push rcx
lea rcx, [rsp + 8h]
call RtlCaptureContext
sub rsp, 20h
jmp vmentry_handler_cpp
vmexit_handler ENDP

END