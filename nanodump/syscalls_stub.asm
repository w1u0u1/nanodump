IFDEF RAX

.CODE

ELSE

.MODEL FLAT, C
.CODE

ASSUME FS:NOTHING

ENDIF

EXTERN SW2_GetSyscallNumber: PROC

IFDEF RAX

NtOpenProcess PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0D2A8CD24h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenProcess ENDP

ELSE

NtOpenProcess PROC
	push 0D2A8CD24h
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtOpenProcess ENDP

ENDIF

IFDEF RAX

NtGetNextProcess PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0D554D4D8h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtGetNextProcess ENDP

ELSE

NtGetNextProcess PROC
	push 0D554D4D8h
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtGetNextProcess ENDP

ENDIF

IFDEF RAX

NtReadVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 019911313h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtReadVirtualMemory ENDP

ELSE

NtReadVirtualMemory PROC
	push 019911313h
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtReadVirtualMemory ENDP

ENDIF

IFDEF RAX

NtClose PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 08D14063Ah        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtClose ENDP

ELSE

NtClose PROC
	push 08D14063Ah
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtClose ENDP

ENDIF

IFDEF RAX

NtOpenProcessToken PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0CC50C8C2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtOpenProcessToken ENDP

ELSE

NtOpenProcessToken PROC
	push 0CC50C8C2h
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtOpenProcessToken ENDP

ENDIF

IFDEF RAX

NtQueryInformationProcess PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0613E9A70h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryInformationProcess ENDP

ELSE

NtQueryInformationProcess PROC
	push 0613E9A70h
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtQueryInformationProcess ENDP

ENDIF

IFDEF RAX

NtQueryVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 085D6B16Bh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryVirtualMemory ENDP

ELSE

NtQueryVirtualMemory PROC
	push 085D6B16Bh
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtQueryVirtualMemory ENDP

ENDIF

IFDEF RAX

NtAdjustPrivilegesToken PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 01B82F59Eh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAdjustPrivilegesToken ENDP

ELSE

NtAdjustPrivilegesToken PROC
	push 01B82F59Eh
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtAdjustPrivilegesToken ENDP

ENDIF

IFDEF RAX

NtAllocateVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 03BAB2F27h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtAllocateVirtualMemory ENDP

ELSE

NtAllocateVirtualMemory PROC
	push 03BAB2F27h
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtAllocateVirtualMemory ENDP

ENDIF

IFDEF RAX

NtFreeVirtualMemory PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 08819849Ch        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtFreeVirtualMemory ENDP

ELSE

NtFreeVirtualMemory PROC
	push 08819849Ch
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtFreeVirtualMemory ENDP

ENDIF

IFDEF RAX

NtCreateFile PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 068DA3BE2h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateFile ENDP

ELSE

NtCreateFile PROC
	push 068DA3BE2h
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtCreateFile ENDP

ENDIF

IFDEF RAX

NtWriteFile PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0F8A3EC11h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWriteFile ENDP

ELSE

NtWriteFile PROC
	push 0F8A3EC11h
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtWriteFile ENDP

ENDIF

IFDEF RAX

NtCreateProcess PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0B02E8865h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtCreateProcess ENDP

ELSE

NtCreateProcess PROC
	push 0B02E8865h
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtCreateProcess ENDP

ENDIF

IFDEF RAX

NtQuerySystemInformation PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 0110D4FDEh        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQuerySystemInformation ENDP

ELSE

NtQuerySystemInformation PROC
	push 0110D4FDEh
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtQuerySystemInformation ENDP

ENDIF

IFDEF RAX

NtDuplicateObject PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 035573FC9h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDuplicateObject ENDP

ELSE

NtDuplicateObject PROC
	push 035573FC9h
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtDuplicateObject ENDP

ENDIF

IFDEF RAX

NtQueryObject PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 003A1FEA3h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtQueryObject ENDP

ELSE

NtQueryObject PROC
	push 003A1FEA3h
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtQueryObject ENDP

ENDIF

IFDEF RAX

NtWaitForSingleObject PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 00F3DE663h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtWaitForSingleObject ENDP

ELSE

NtWaitForSingleObject PROC
	push 00F3DE663h
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtWaitForSingleObject ENDP

ENDIF

IFDEF RAX

NtDeleteFile PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 03CFA6BC6h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtDeleteFile ENDP

ELSE

NtDeleteFile PROC
	push 03CFA6BC6h
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtDeleteFile ENDP

ENDIF

IFDEF RAX

NtTerminateProcess PROC
	mov [rsp +8], rcx          ; Save registers.
	mov [rsp+16], rdx
	mov [rsp+24], r8
	mov [rsp+32], r9
	sub rsp, 28h
	mov ecx, 04BAF5606h        ; Load function hash into ECX.
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add rsp, 28h
	mov rcx, [rsp +8]          ; Restore registers.
	mov rdx, [rsp+16]
	mov r8, [rsp+24]
	mov r9, [rsp+32]
	mov r10, rcx
	syscall                    ; Invoke system call.
	ret
NtTerminateProcess ENDP

ELSE

NtTerminateProcess PROC
	push 04BAF5606h
	call SW2_GetSyscallNumber  ; Resolve function hash into syscall number.
	add esp, 4
	mov ecx, fs:[0c0h]
	test ecx, ecx
	jne _wow64
	lea edx, [esp+4h]
	INT 02eh
	ret
	_wow64:
	xor ecx, ecx
	lea edx, [esp+4h]
	call dword ptr fs:[0c0h]
	ret
NtTerminateProcess ENDP

ENDIF

end