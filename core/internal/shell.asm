.code
		;//helper
		;std::uintptr_t readPage;  // 0
		;std::uintptr_t writePage; // 8
		;std::uintptr_t original;  // 16


internal_shell PROC
	pushfq
	push rcx
	
read_start:
	push rdx
	push rax

	mov rdx, [helper]
	mov rax, [helper+08h]

read_loop:
	mov rcx, [rdx]
	mov rcx, [rdx]
	mov [rax], rcx

	add rdx, 8
	add rax, 8
	
	cmp QWORD PTR [rdx], 0
	jne read_loop
	
	pop rax
	pop rdx
	pop rcx
	popfq

	jmp QWORD PTR [helper+010h]

helper:
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
internal_shell ENDP

END