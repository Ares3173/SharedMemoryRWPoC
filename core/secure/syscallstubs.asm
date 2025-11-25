.code


AllSyscallStub PROC
mov r10, rcx
mov eax, DWORD PTR gs:[016B4h]
syscall
ret
AllSyscallStub ENDP

END