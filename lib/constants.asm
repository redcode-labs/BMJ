; -------------- [SYSCALL NUMBERS DECLARATIONS]
%define SYS_READ 0
%define SYS_WRITE 1
%define SYS_OPEN 2
%define SYS_CLOSE 3
%define SYS_STAT 4
%define SYS_FSTAT 5
%define SYS_LSTAT 6
%define SYS_POLL 7
%define SYS_LSEEK 8
%define SYS_MMAP 9
%define SYS_MPROTECT 10
%define SYS_MUNMAP 11
%define SYS_BRK 12
%define SYS_RT_SIGACTION 13
%define SYS_RT_SIGPROCMASK 14
%define SYS_RT_SIGRETURN 15
%define SYS_IOCTL 16
%define SYS_PREAD64 17
%define SYS_PWRITE64 18
%define SYS_READVV 2
%define SYS_PIPE 22
%define SYS_SELECT 23
%define SYS_SCHED_YIELD 24
%define SYS_MREMAP 25
%define SYS_MSYNC 26
%define SYS_MINCORE 27
%define SYS_MADVISE 28
%define SYS_SHMGET 29
%define SYS_SHMAT 30
%define SYS_SHMCTL 31
%define SYS_DUP 32
%define SYS_DUP2 33
%define SYS_PAUSE 34
%define SYS_NANOSLEEP 35
%define SYS_GETITIMER 36
%define SYS_ALARM 37
%define SYS_SETITIMER 38
%define SYS_GETPID 39
%define SYS_SENDFILE 40
%define SYS_SOCKET 41
%define SYS_CONNECT 42
%define SYS_ACCEPT 43
%define SYS_SENDTO 44
%define SYS_RECVFROM 45
%define SYS_SENDMSG 46
%define SYS_RECVMSG 47
%define SYS_SHUTDOWN 48
%define SYS_BIND 49
%define SYS_LISTEN 50
%define SYS_GETSOCKNAME 51
%define SYS_GETPEERNAME 52
%define SYS_SOCKETPAIR 53
%define SYS_SETSOCKOPT 54
%define SYS_GETSOCKOPT 55
%define SYS_CLONE 56
%define SYS_FORK 57
%define SYS_VFORK 58
%define SYS_EXECVE 59
%define SYS_EXIT 60
%define SYS_WAIT4 61
%define SYS_KILL 62
%define SYS_UNAME 63
%define SYS_SEMGET 64
%define SYS_SEMOP 65
%define SYS_SEMCTL 66
%define SYS_SHMDT 67
%define SYS_MSGGET 68
%define SYS_MSGSND 69
%define SYS_MSGRCV 70
%define SYS_MSGCTL 71
%define SYS_FCNTL 72
%define SYS_FLOCK 73
%define SYS_FSYNC 74
%define SYS_FDATASYNC 75
%define SYS_TRUNCATE 76
%define SYS_FTRUNCATE 77
%define SYS_GETDENTS 78
%define SYS_GETCWD 79
%define SYS_CHDIR 80
%define SYS_FCHDIR 81
%define SYS_RENAME 82
%define SYS_MKDIR 83
%define SYS_RMDIR 84
%define SYS_CREAT 85
%define SYS_LINK 86
%define SYS_UNLINK 87
%define SYS_SYMLINK 88
%define SYS_READLINK 89
%define SYS_CHMOD 90
%define SYS_FCHMOD 91
%define SYS_CHOWN 92
%define SYS_FCHOWN 93
%define SYS_LCHOWN 94
%define SYS_UMASK 95
%define SYS_GETTIMEOFDAY 96
%define SYS_GETRLIMIT 97
%define SYS_GETRUSAGE 98
%define SYS_SYSINFO 99
%define SYS_TIMES 100
%define SYS_PTRACE 101
%define SYS_GETUID 102
%define SYS_SYSLOG 103
%define SYS_GETGID 104
%define SYS_SETUID 105
%define SYS_SETGID 106
%define SYS_GETEUID 107
%define SYS_GETEGID 108
%define SYS_SETPGID 109
%define SYS_GETPPID 110
%define SYS_GETPGRP 111
%define SYS_SETSID 112
%define SYS_SETREUID 113
%define SYS_SETREGID 114
%define SYS_GETGROUPS 115
%define SYS_SETGROUPS 116
%define SYS_SETRESUID 117
%define SYS_GETRESUID 118
%define SYS_SETRESGID 119
%define SYS_GETRESGID 120
%define SYS_GETPGID 121
%define SYS_SETFSUID 122
%define SYS_SETFSGID 123
%define SYS_GETSID 124
%define SYS_CAPGET 125
%define SYS_CAPSET 126
%define SYS_RT_SIGPENDING 127
%define SYS_RT_SIGTIMEDWAIT 128
%define SYS_RT_SIGQUEUEINFO 129
%define SYS_RT_SIGSUSPEND 130
%define SYS_SIGALTSTACK 131
%define SYS_UTIME 132
%define SYS_MKNOD 133
%define SYS_USELIB 134
%define SYS_PERSONALITY 135
%define SYS_USTAT 136
%define SYS_STATFS 137
%define SYS_FSTATFS 138
%define SYS_SYSFS 139
%define SYS_GETPRIORITY 140
%define SYS_SETPRIORITY 141
%define SYS_SCHED_SETPARAM 142
%define SYS_SCHED_GETPARAM 143
%define SYS_SCHED_SETSCHEDULER 144
%define SYS_SCHED_GETSCHEDULER 145
%define SYS_SCHED_GET_PRIORITY_MAX 146
%define SYS_SCHED_GET_PRIORITY_MIN 147
%define SYS_SCHED_RR_GET_INTERVAL 148
%define SYS_MLOCK 149
%define SYS_MUNLOCK 150
%define SYS_MLOCKALL 151
%define SYS_MUNLOCKALL 152
%define SYS_VHANGUP 153
%define SYS_MODIFY_LDT 154
%define SYS_PIVOT_ROOT 155
%define SYS__SYSCTL 156
%define SYS_PRCTL 157
%define SYS_ARCH_PRCTL 158
%define SYS_ADJTIMEX 159
%define SYS_SETRLIMIT 160
%define SYS_CHROOT 161
%define SYS_SYNC 162
%define SYS_ACCT 163
%define SYS_SETTIMEOFDAY 164
%define SYS_MOUNT 165
%define SYS_UMOUNT2 166
%define SYS_SWAPON 167
%define SYS_SWAPOFF 168
%define SYS_REBOOT 169
%define SYS_SETHOSTNAME 170
%define SYS_SETDOMAINNAME 171
%define SYS_IOPL 172
%define SYS_IOPERM 173
%define SYS_CREATE_MODULE 174
%define SYS_INIT_MODULE 175
%define SYS_DELETE_MODULE 176
%define SYS_GET_KERNEL_SYMS 177
%define SYS_QUERY_MODULE 178
%define SYS_QUOTACTL 179
%define SYS_NFSSERVCTL 180
%define SYS_GETPMSG 181
%define SYS_PUTPMSG 182
%define SYS_AFS_SYSCALL 183
%define SYS_TUXCALL 184
%define SYS_SECURITY 185
%define SYS_GETTID 186
%define SYS_READAHEAD 187
%define SYS_SETXATTR 188
%define SYS_LSETXATTR 189
%define SYS_FSETXATTR 190
%define SYS_GETXATTR 191
%define SYS_LGETXATTR 192
%define SYS_FGETXATTR 193
%define SYS_LISTXATTR 194
%define SYS_LLISTXATTR 195
%define SYS_FLISTXATTR 196
%define SYS_REMOVEXATTR 197
%define SYS_LREMOVEXATTR 198
%define SYS_FREMOVEXATTR 199
%define SYS_TKILL 200
%define SYS_TIME 201
%define SYS_FUTEX 202
%define SYS_SCHED_SETAFFINITY 203
%define SYS_SCHED_GETAFFINITY 204
%define SYS_SET_THREAD_AREA 205
%define SYS_IO_SETUP 206
%define SYS_IO_DESTROY 207
%define SYS_IO_GETEVENTS 208
%define SYS_IO_SUBMIT 209
%define SYS_IO_CANCEL 210
%define SYS_GET_THREAD_AREA 211
%define SYS_LOOKUP_DCOOKIE 212
%define SYS_EPOLL_CREATE 213
%define SYS_EPOLL_CTL_OLD 214
%define SYS_EPOLL_WAIT_OLD 215
%define SYS_REMAP_FILE_PAGES 216
%define SYS_GETDENTS64 217
%define SYS_SET_TID_ADDRESS 218
%define SYS_RESTART_SYSCALL 219
%define SYS_SEMTIMEDOP 220
%define SYS_FADVISE64 221
%define SYS_TIMER_CREATE 222
%define SYS_TIMER_SETTIME 223
%define SYS_TIMER_GETTIME 224
%define SYS_TIMER_GETOVERRUN 225
%define SYS_TIMER_DELETE 226
%define SYS_CLOCK_SETTIME 227
%define SYS_CLOCK_GETTIME 228
%define SYS_CLOCK_GETRES 229
%define SYS_CLOCK_NANOSLEEP 230
%define SYS_EXIT_GROUP 231
%define SYS_EPOLL_WAIT 232
%define SYS_EPOLL_CTL 233
%define SYS_TGKILL 234
%define SYS_UTIMES 235
%define SYS_VSERVER 236
%define SYS_MBIND 237
%define SYS_SET_MEMPOLICY 238
%define SYS_GET_MEMPOLICY 239
%define SYS_MQ_OPEN 240
%define SYS_MQ_UNLINK 241
%define SYS_MQ_TIMEDSEND 242
%define SYS_MQ_TIMEDRECEIVE 243
%define SYS_MQ_NOTIFY 244
%define SYS_MQ_GETSETATTR 245
%define SYS_KEXEC_LOAD 246
%define SYS_WAITID 247
%define SYS_ADD_KEY 248
%define SYS_REQUEST_KEY 249
%define SYS_KEYCTL 250
%define SYS_IOPRIO_SET 251
%define SYS_IOPRIO_GET 252
%define SYS_INOTIFY_INIT 253
%define SYS_INOTIFY_ADD_WATCH 254
%define SYS_INOTIFY_RM_WATCH 255
%define SYS_MIGRATE_PAGES 256
%define SYS_OPENAT 257
%define SYS_MKDIRAT 258
%define SYS_MKNODAT 259
%define SYS_FCHOWNAT 260
%define SYS_FUTIMESAT 261
%define SYS_NEWFSTATAT 262
%define SYS_UNLINKAT 263
%define SYS_RENAMEAT 264
%define SYS_LINKAT 265
%define SYS_SYMLINKAT 266
%define SYS_READLINKAT 267
%define SYS_FCHMODAT 268
%define SYS_FACCESSAT 269
%define SYS_PSELECT6 270
%define SYS_PPOLL 271
%define SYS_UNSHARE 272
%define SYS_SET_ROBUST_LIST 273
%define SYS_GET_ROBUST_LIST 274
%define SYS_SPLICE 275
%define SYS_TEE 276
%define SYS_SYNC_FILE_RANGE 277
%define SYS_VMSPLICE 278
%define SYS_MOVE_PAGES 279
%define SYS_UTIMENSAT 280
%define SYS_EPOLL_PWAIT 281
%define SYS_SIGNALFD 282
%define SYS_TIMERFD_CREATE 283
%define SYS_EVENTFD 284
%define SYS_FALLOCATE 285
%define SYS_TIMERFD_SETTIME 286
%define SYS_TIMERFD_GETTIME 287
%define SYS_ACCEPT4 288
%define SYS_SIGNALFD4 289
%define SYS_EVENTFD2 290
%define SYS_EPOLL_CREATE1 291
%define SYS_DUP3 292
%define SYS_PIPE2 293
%define SYS_INOTIFY_INIT1 294
%define SYS_PREADV 295
%define SYS_PWRITEV 296
%define SYS_RT_TGSIGQUEUEINFO 297
%define SYS_PERF_EVENT_OPEN 298
%define SYS_RECVMMSG 299
%define SYS_FANOTIFY_INIT 300
%define SYS_FANOTIFY_MARK 301
%define SYS_PRLIMIT64 302
%define SYS_NAME_TO_HANDLE_AT 303
%define SYS_OPEN_BY_HANDLE_AT 304
%define SYS_CLOCK_ADJTIME 305
%define SYS_SYNCFS 306
%define SYS_SENDMMSG 307
%define SYS_SETNS 308
%define SYS_GETCPU 309
%define SYS_PROCESS_VM_READV 310
%define SYS_PROCESS_VM_WRITEV 311
%define SYS_KCMP 312
%define SYS_FINIT_MODULE 313
%define SYS_SCHED_SETATTR 314
%define SYS_SCHED_GETATTR 315
%define SYS_RENAMEAT2 316
%define SYS_SECCOMP 317
%define SYS_GETRANDOM 318
%define SYS_MEMFD_CREATE 319
%define SYS_KEXEC_FILE_LOAD 320
%define SYS_BPF 321
%define SYS_EXECVEAT 322
%define SYS_USERFAULTFD 323
%define SYS_MEMBARRIER 324
%define SYS_MLOCK2 325

; -------------- [CAPABILITIES]
%define CAP_CHOWN             0
%define CAP_DAC_OVERRIDE      1
%define CAP_DAC_READ_SEARCH   2
%define CAP_FOWNER            3
%define CAP_FSETID            4
%define CAP_KILL              5
%define CAP_SETGID            6
%define CAP_SETUID            7
%define CAP_SETPCAP           8
%define CAP_LINUX_IMMUTABLE   9
%define CAP_NET_BIND_SERVICE  10
%define CAP_NET_BROADCAST     11
%define CAP_NET_ADMIN         12
%define CAP_NET_RAW           13
%define CAP_IPC_LOCK          14
%define CAP_IPC_OWNER         15
%define CAP_SYS_MODULE        16
%define CAP_SYS_RAWIO         17
%define CAP_SYS_CHROOT        18
%define CAP_SYS_PTRACE        19
%define CAP_SYS_PACCT         20
%define CAP_SYS_ADMIN         21
%define CAP_SYS_BOOT          22
%define CAP_SYS_NICE          23
%define CAP_SYS_RESOURCE      24
%define CAP_SYS_TIME          25
%define CAP_SYS_TTY_CONFIG    26
%define CAP_MKNOD             27
%define CAP_LEASE             28
%define CAP_AUDIT_WRITE       29
%define CAP_AUDIT_CONTROL     30
%define CAP_SETFCAP	          31
%define CAP_MAC_OVERRIDE      32
%define CAP_MAC_ADMIN         33
%define CAP_SYSLOG            34
%define CAP_WAKE_ALARM        35
%define CAP_BLOCK_SUSPEND     36
%define CAP_AUDIT_READ		  37
%define CAP_PERFMON		      38
%define CAP_BPF			      39

%define PR_SET_PDEATHSIG         1 
%define PR_GET_PDEATHSIG         2 
%define PR_GET_DUMPABLE          3
%define PR_SET_DUMPABLE          4
%define PR_GET_UNALIGN	         5
%define PR_SET_UNALIGN	         6
%define PR_GET_KEEPCAPS          7
%define PR_SET_KEEPCAPS          8
%define PR_GET_FPEMU             9
%define PR_SET_FPEMU             10
%define PR_GET_FPEXC	         11
%define PR_SET_FPEXC	         12
%define PR_GET_TIMING            13
%define PR_SET_TIMING            14
%define PR_TIMING_STATISTICAL    0  
%define PR_TIMING_TIMESTAMP      1  
%define PR_SET_NAME              15	
%define PR_GET_NAME              16	
%define PR_GET_ENDIAN            19
%define PR_SET_ENDIAN	         20
%define PR_ENDIAN_BIG		     0
%define PR_ENDIAN_LITTLE	     1
%define PR_ENDIAN_PPC_LITTLE	 2	
%define PR_GET_SECCOMP	         21
%define PR_SET_SECCOMP	         22
%define PR_CAPBSET_READ          23
%define PR_CAPBSET_DROP          24
%define PR_GET_TSC               25
%define PR_SET_TSC               26
%define PR_TSC_ENABLE	         1
%define PR_TSC_SIGSEGV		     2
%define PR_GET_SECUREBITS        27
%define PR_SET_SECUREBITS        28
%define PR_SET_TIMERSLACK        29
%define PR_GET_TIMERSLACK        30
%define PR_TASK_PERF_EVENTS_DISABLE  31
%define PR_TASK_PERF_EVENTS_ENABLE	 32
%define PR_MCE_KILL	             33
%define PR_MCE_KILL_CLEAR        0
%define PR_MCE_KILL_SET          1
%define PR_MCE_KILL_LATE         0
%define PR_MCE_KILL_EARLY        1
%define PR_MCE_KILL_DEFAULT      2
%define PR_MCE_KILL_GET          34
%define PR_SET_MM		         35
%define PR_SET_MM_START_CODE	 1
%define PR_SET_MM_END_CODE		 2
%define PR_SET_MM_START_DATA	 3
%define PR_SET_MM_END_DATA		 4
%define PR_SET_MM_START_STACK	 5
%define PR_SET_MM_START_BRK		 6
%define PR_SET_MM_BRK			 7
%define PR_SET_MM_ARG_START		 8
%define PR_SET_MM_ARG_END		 9
%define PR_SET_MM_ENV_START		 10
%define PR_SET_MM_ENV_END		 11
%define PR_SET_MM_AUXV			 12
%define PR_SET_MM_EXE_FILE		 13
%define PR_SET_MM_MAP			 14
%define PR_SET_MM_MAP_SIZE		 15
%define PR_SET_PTRACER           0x59616d61
%define PR_SET_CHILD_SUBREAPER	 36
%define PR_GET_CHILD_SUBREAPER	 37
%define PR_SET_NO_NEW_PRIVS 	 38
%define PR_GET_NO_NEW_PRIVS 	 39
%define PR_GET_TID_ADDRESS	     40
%define PR_SET_THP_DISABLE	     41
%define PR_GET_THP_DISABLE	     42
%define PR_MPX_ENABLE_MANAGEMENT     43
%define PR_MPX_DISABLE_MANAGEMENT    44
%define PR_SET_FP_MODE		         45
%define PR_GET_FP_MODE		         46
%define PR_CAP_AMBIENT			     47
%define PR_CAP_AMBIENT_IS_SET		 1
%define PR_CAP_AMBIENT_RAISE		 2
%define PR_CAP_AMBIENT_LOWER		 3
%define PR_CAP_AMBIENT_CLEAR_ALL	 4

%define SECONDS  1
%define MINUTES  60
%define HOURS  3600
%define DAYS  86400 
%define YES  1
%define NO   0
%define TRUE 1
%define FALSE   0
%define MAX_PRIO -20
%define MIN_PRIO 19

%define _ASM_X86_SIGNAL_H
%define NSIG            32
%define SIGHUP           1
%define SIGINT           2
%define SIGQUIT          3
%define SIGILL           4
%define SIGTRAP          5
%define SIGABRT          6
%define SIGIOT           6
%define SIGBUS           7
%define SIGFPE           8
%define SIGKILL          9
%define SIGUSR1         10
%define SIGSEGV         11
%define SIGUSR2         12
%define SIGPIPE         13
%define SIGALRM         14
%define SIGTERM         15
%define SIGSTKFLT       16
%define SIGCHLD         17
%define SIGCONT         18
%define SIGSTOP         19
%define SIGTSTP         20
%define SIGTTIN         21
%define SIGTTOU         22
%define SIGURG          23
%define SIGXCPU         24
%define SIGXFSZ         25
%define SIGVTALRM       26
%define SIGPROF         27
%define SIGWINCH        28
%define SIGIO           29
%define SIGPOLL         SIGIO
%define SIGLOST         29
%define SIGPWR          30
%define SIGSYS          31
%define SIGUNUSED       31
%define SIGRTMIN        32
%define SA_NOCLDSTOP    0x00000001u
%define SA_NOCLDWAIT    0x00000002u
%define SA_SIGINFO      0x00000004u
%define SA_ONSTACK      0x08000000u
%define SA_RESTART      0x10000000u
%define SA_NODEFER      0x40000000u
%define SA_RESETHAND    0x80000000u
%define SA_NOMASK       SA_NODEFER
%define SA_ONESHOT      SA_RESETHAND
%define SIG_BLOCK          1
%define SIG_UNBLOCK        2
%define SIG_SETMASK        3

%define O_ACCMODE	00000003
%define O_RDONLY	00000000
%define O_WRONLY	00000001
%define O_RDWR		00000002
%define O_CREAT		00000100
%define O_EXCL		00000200	
%define O_NOCTTY	00000400	
%define O_TRUNC		00001000	
%define O_APPEND	00002000
%define O_NONBLOCK	00004000
%define O_DSYNC		00010000	
%define FASYNC		00020000	
%define O_DIRECT	00040000	
%define O_LARGEFILE	00100000
%define O_DIRECTORY	00200000	
%define O_NOFOLLOW	00400000	
%define O_NOATIME	01000000
%define O_CLOEXEC	02000000	
%define __O_SYNC	04000000
%define O_SYNC		(__O_SYNC|O_DSYNC)
%define O_PATH		010000000
%define O_NDELAY	O_NONBLOCK%
%define F_DUPFD		0	
%define F_GETFD		1
%define F_SETFD		2	
%define F_GETFL		3	
%define F_SETFL		4	
%define F_GETLK		5
%define F_SETLK		6
%define F_SETLKW	7
%define F_SETOWN	8	
%define F_GETOWN	9	
%define F_SETSIG	10	
%define F_GETSIG	11	
%define F_GETLK64	12	/
%define F_SETLK64	13
;%define F_SETLKW64	14%
%define F_SETOWN_EX	15
;%define F_GETOWN_EX	16%
;%define F_GETOWNER_UIDS	17%
%define F_OFD_GETLK	36
%define F_OFD_SETLK	37
;%define F_OFD_SETLKW	38%
%define F_OWNER_TID	0
%define F_OWNER_PID	1
%define F_OWNER_PGRP	2
%define FD_CLOEXEC	1	
%define F_RDLCK		0
%define F_WRLCK		1
%define F_UNLCK		2
%define F_EXLCK		4	
%define F_SHLCK		8	
%define LOCK_SH		1	
%define LOCK_EX		2	
%define LOCK_NB		4	
%define LOCK_MAND	32	
%define LOCK_READ	64	
%define LOCK_WRITE	128	
%define LOCK_RW		192	
%define F_LINUX_SPECIFIC_BASE	1024

; - - - [ POWER MANAGMENT CONSTANTS ] - - -
%define _SYS_REBOOT_H	1
%define RB_AUTOBOOT	0x01234567
%define RB_HALT_SYSTEM	0xcdef0123
%define RB_ENABLE_CAD	0x89abcdef
%define RB_DISABLE_CAD	0
%define RB_POWER_OFF	0x4321fedc
%define RB_SW_SUSPEND	0xd000fce2
%define RB_KEXEC	0x45584543

; - - - [ DEBUGGING ] - - -
%define INFO  "[ * ] --- "
%define ERROR "[ x ] --- "
%define GOOD  "[ + ] --- "

; - - - [ FILE OPS ] - - -
%define RW 0x402
%define EMPTY_STRING ""

; - - - [ LKM LOADING ] - - -
%define MODULE_INIT_IGNORE_MODVERSIONS	1
%define MODULE_INIT_IGNORE_VERMAGIC	2

; - - - [ MEMFD CONSTANTS ] - - - 
%define MFD_CLOEXEC		0x0001U
%define MFD_ALLOW_SEALING	0x0002U
%define MFD_HUGETLB		0x0004U
;#define MFD_HUGE_SHIFT
;#define MFD_HUGE_MASK
;#define MFD_HUGE_64KB
;#define MFD_HUGE_512KB
;#define MFD_HUGE_1MB	
;#define MFD_HUGE_2MB	
;#define MFD_HUGE_8MB	
;#define MFD_HUGE_16MB
;#define MFD_HUGE_32MB
;#define MFD_HUGE_256MB
;#define MFD_HUGE_512MB
;#define MFD_HUGE_1GB	
;#define MFD_HUGE_2GB	
;#define MFD_HUGE_16GB

%define HUGETLB_FLAG_ENCODE_SHIFT	26

%define HUGETLB_FLAG_ENCODE_16KB	 14 << HUGETLB_FLAG_ENCODE_SHIFT
%define HUGETLB_FLAG_ENCODE_64KB	 16 << HUGETLB_FLAG_ENCODE_SHIFT
%define HUGETLB_FLAG_ENCODE_512KB 	 19 << HUGETLB_FLAG_ENCODE_SHIFT
%define HUGETLB_FLAG_ENCODE_1MB		 20 << HUGETLB_FLAG_ENCODE_SHIFT
%define HUGETLB_FLAG_ENCODE_2MB		 21 << HUGETLB_FLAG_ENCODE_SHIFT
%define HUGETLB_FLAG_ENCODE_8MB		 23 << HUGETLB_FLAG_ENCODE_SHIFT
%define HUGETLB_FLAG_ENCODE_16MB	 24 << HUGETLB_FLAG_ENCODE_SHIFT
%define HUGETLB_FLAG_ENCODE_32MB	 25 << HUGETLB_FLAG_ENCODE_SHIFT
%define HUGETLB_FLAG_ENCODE_256MB    28 << HUGETLB_FLAG_ENCODE_SHIFT
%define HUGETLB_FLAG_ENCODE_512MB    29 << HUGETLB_FLAG_ENCODE_SHIFT
%define HUGETLB_FLAG_ENCODE_1GB		 30 << HUGETLB_FLAG_ENCODE_SHIFT
%define HUGETLB_FLAG_ENCODE_2GB		 31 << HUGETLB_FLAG_ENCODE_SHIFT
%define HUGETLB_FLAG_ENCODE_16GB	 34 << HUGETLB_FLAG_ENCODE_SHIFT

; - - - [ PRCTL CONSTANTS ] - - -
%define F_SEAL_SEAL	0x0001	
%define F_SEAL_SHRINK	0x0002
%define F_SEAL_GROW	0x0004
%define F_SEAL_WRITE	0x0008
%define F_SEAL_FUTURE_WRITE	0x0010 
%define F_GET_RW_HINT		F_LINUX_SPECIFIC_BASE + 11
%define F_SET_RW_HINT		F_LINUX_SPECIFIC_BASE + 12
%define F_GET_FILE_RW_HINT	F_LINUX_SPECIFIC_BASE + 13
%define F_SET_FILE_RW_HINT	F_LINUX_SPECIFIC_BASE + 14
%define RWH_WRITE_LIFE_NOT_SET	0
%define RWH_WRITE_LIFE_NONE	1
%define RWH_WRITE_LIFE_SHORT	2
%define RWH_WRITE_LIFE_MEDIUM	3
%define RWH_WRITE_LIFE_LONG	4
%define RWH_WRITE_LIFE_EXTREME	5

%define DN_ACCESS	0x00000001	/* File accessed */
%define DN_MODIFY	0x00000002	/* File modified */
%define DN_CREATE	0x00000004	/* File created */
%define DN_DELETE	0x00000008	/* File removed */
%define DN_RENAME	0x00000010	/* File renamed */
%define DN_ATTRIB	0x00000020	/* File changed attibutes */
%define DN_MULTISHOT	0x80000000	/* Don't remove notifier */

%define AT_FDCWD		-100    
%define AT_SYMLINK_NOFOLLOW	0x100 
%define AT_EACCESS		0x200	
%define AT_REMOVEDIR		0x200 
%define AT_SYMLINK_FOLLOW	0x400  
%define AT_NO_AUTOMOUNT		0x800
%define AT_EMPTY_PATH		0x1000	
%define AT_STATX_SYNC_TYPE	0x6000	
%define AT_STATX_SYNC_AS_STAT	0x0000	
%define AT_STATX_FORCE_SYNC	0x2000	
%define AT_STATX_DONT_SYNC	0x4000	
%define AT_RECURSIVE		0x8000	

%define SOCK_STREAM	 1
%define SOCK_DGRAM	 2
%define SOCK_RAW	3
%define SOCK_RDM	4
%define SOCK_SEQPACKET	5
%define SOCK_DCCP	6
%define SOCK_PACKET	10
%define AF_UNSPEC	0
%define AF_UNIX		1	/* Unix domain sockets 		*/
%define AF_LOCAL	1	/* POSIX name for AF_UNIX	*/
%define AF_INET		2	/* Internet IP Protocol 	*/
%define AF_AX25		3	/* Amateur Radio AX.25 		*/
%define AF_IPX		4	/* Novell IPX 			*/
%define AF_APPLETALK	5	/* AppleTalk DDP 		*/
%define AF_NETROM	6	/* Amateur Radio NET/ROM 	*/
%define AF_BRIDGE	7	/* Multiprotocol bridge 	*/
%define AF_ATMPVC	8	/* ATM PVCs			*/
%define AF_X25		9	/* Reserved for X.25 project 	*/
%define AF_INET6	10	/* IP version 6			*/
%define AF_ROSE		11	/* Amateur Radio X.25 PLP	*/
%define AF_DECnet	12	/* Reserved for DECnet project	*/
%define AF_NETBEUI	13	/* Reserved for 802.2LLC project*/
%define AF_SECURITY	14	/* Security callback pseudo AF */
%define AF_KEY		15      /* PF_KEY key management API */
%define AF_NETLINK	16
%define AF_ROUTE	AF_NETLINK /* Alias to emulate 4.4BSD */
%define AF_PACKET	17	/* Packet family		*/
%define AF_ASH		18	/* Ash				*/
%define AF_ECONET	19	/* Acorn Econet			*/
%define AF_ATMSVC	20	/* ATM SVCs			*/
%define AF_RDS		21	/* RDS sockets 			*/
%define AF_SNA		22	/* Linux SNA Project (nutters!) */
%define AF_IRDA		23	/* IRDA sockets			*/
%define AF_PPPOX	24	/* PPPoX sockets		*/
%define AF_WANPIPE	25	/* Wanpipe API Sockets */
%define AF_LLC		26	/* Linux LLC			*/
%define AF_IB		27	/* Native InfiniBand address	*/
%define AF_MPLS		28	/* MPLS */
%define AF_CAN		29	/* Controller Area Network      */
%define AF_TIPC		30	/* TIPC sockets			*/
%define AF_BLUETOOTH	31	/* Bluetooth sockets 		*/
%define AF_IUCV		32	/* IUCV sockets			*/
%define AF_RXRPC	33	/* RxRPC sockets 		*/
%define AF_ISDN		34	/* mISDN sockets 		*/
%define AF_PHONET	35	/* Phonet sockets		*/
%define AF_IEEE802154	36	/* IEEE802154 sockets		*/
%define AF_CAIF		37	/* CAIF sockets			*/
%define AF_ALG		38	/* Algorithm sockets		*/
%define AF_NFC		39	/* NFC sockets			*/
%define AF_VSOCK	40	/* vSockets			*/
%define AF_KCM		41	/* Kernel Connection Multiplexor*/
%define AF_QIPCRTR	42	/* Qualcomm IPC Router          */
%define AF_SMC		43	
%define AF_XDP		44	/* XDP sockets			*/
%define AF_MAX		45	/* For now.. */

%define PF_UNSPEC	AF_UNSPEC
%define PF_UNIX		AF_UNIX
%define PF_LOCAL	AF_LOCAL
%define PF_INET		AF_INET
%define PF_AX25		AF_AX25
%define PF_IPX		AF_IPX
%define PF_APPLETALK	AF_APPLETALK
%define	PF_NETROM	AF_NETROM
%define PF_BRIDGE	AF_BRIDGE
%define PF_ATMPVC	AF_ATMPVC
%define PF_X25		AF_X25
%define PF_INET6	AF_INET6
%define PF_ROSE		AF_ROSE
%define PF_DECnet	AF_DECnet
%define PF_NETBEUI	AF_NETBEUI
%define PF_SECURITY	AF_SECURITY
%define PF_KEY		AF_KEY
%define PF_NETLINK	AF_NETLINK
%define PF_ROUTE	AF_ROUTE
%define PF_PACKET	AF_PACKET
%define PF_ASH		AF_ASH
%define PF_ECONET	AF_ECONET
%define PF_ATMSVC	AF_ATMSVC
%define PF_RDS		AF_RDS
%define PF_SNA		AF_SNA
%define PF_IRDA		AF_IRDA
%define PF_PPPOX	AF_PPPOX
%define PF_WANPIPE	AF_WANPIPE
%define PF_LLC		AF_LLC
%define PF_IB		AF_IB
%define PF_MPLS		AF_MPLS
%define PF_CAN		AF_CAN
%define PF_TIPC		AF_TIPC
%define PF_BLUETOOTH	AF_BLUETOOTH
%define PF_IUCV		AF_IUCV
%define PF_RXRPC	AF_RXRPC
%define PF_ISDN		AF_ISDN
%define PF_PHONET	AF_PHONET
%define PF_IEEE802154	AF_IEEE802154
%define PF_CAIF		AF_CAIF
%define PF_ALG		AF_ALG
%define PF_NFC		AF_NFC
%define PF_VSOCK	AF_VSOCK
%define PF_KCM		AF_KCM
%define PF_QIPCRTR	AF_QIPCRTR
%define PF_SMC		AF_SMC
%define PF_XDP		AF_XDP
%define PF_MAX		AF_MAX

%define SOMAXCONN	4096%
%define MSG_OOB		1
%define MSG_PEEK	2
%define MSG_DONTROUTE	4
%define MSG_TRYHARD     4       /* Synonym for MSG_DONTROUTE for DECnet */
%define MSG_CTRUNC	8
%define MSG_PROBE	0x10	/* Do not send. Only probe path f.e. for MTU */
%define MSG_TRUNC	0x20
%define MSG_DONTWAIT	0x40	/* Nonblocking io		 */
%define MSG_EOR         0x80	/* End of record */
%define MSG_WAITALL	0x100	/* Wait for a full request */
%define MSG_FIN         0x200
%define MSG_SYN		0x400
%define MSG_CONFIRM	0x800	/* Confirm path validity */
%define MSG_RST		0x1000
%define MSG_ERRQUEUE	0x2000	/* Fetch message from error queue */
%define MSG_NOSIGNAL	0x4000	/* Do not generate SIGPIPE */
%define MSG_MORE	0x8000	/* Sender will send more */
%define MSG_WAITFORONE	0x10000	/* recvmmsg(): block until 1+ packets avail */
%define MSG_SENDPAGE_NOPOLICY 0x10000 /* sendpage() internal : do no apply policy */
%define MSG_SENDPAGE_NOTLAST 0x20000 /* sendpage() internal : not the last page */
%define MSG_BATCH	0x40000 /* sendmmsg(): more messages coming */
%define MSG_EOF         MSG_FIN
%define MSG_NO_SHARED_FRAGS 0x80000 /* sendpage() internal : page frags are not shared */
%define MSG_SENDPAGE_DECRYPTED	0x100000 
%define MSG_ZEROCOPY	0x4000000	
%define MSG_FASTOPEN	0x20000000	
%define MSG_CMSG_CLOEXEC 0x40000000	
%define MSG_CMSG_COMPAT	0		


%define SOL_IP		0
%define SOL_TCP		6
%define SOL_UDP		17
%define SOL_IPV6	41
%define SOL_ICMPV6	58
%define SOL_SCTP	132
%define SOL_UDPLITE	136     /* UDP-Lite (RFC 3828) */
%define SOL_RAW		255
%define SOL_IPX		256
%define SOL_AX25	257
%define SOL_ATALK	258
%define SOL_NETROM	259
%define SOL_ROSE	260
%define SOL_DECNET	261
%define	SOL_X25		262
%define SOL_PACKET	263
%define SOL_ATM		264	/* ATM layer (cell level) */
%define SOL_AAL		265	/* ATM Adaption Layer (packet level) */
%define SOL_IRDA        266
%define SOL_NETBEUI	267
%define SOL_LLC		268
%define SOL_DCCP	269
%define SOL_NETLINK	270
%define SOL_TIPC	271
%define SOL_RXRPC	272
%define SOL_PPPOL2TP	273
%define SOL_BLUETOOTH	274
%define SOL_PNPIPE	275
%define SOL_RDS		276
%define SOL_IUCV	277
%define SOL_CAIF	278
%define SOL_ALG		279
%define SOL_NFC		280
%define SOL_KCM		281
%define SOL_TLS		282
%define SOL_XDP		283
%define IPX_TYPE	1

; - - - [ NETWORKING ALIASES ] - - -
%define LOCALHOST 0x0100007f
%define LOOPBACK  0x00000000
%define BROADCAST 0xffffffff

; - - -  [TIMESTAMP CONSTANTS ] - - -
%define PRESENT 0x00000000
%define FUTURE  0xffffffff

; - - - [ LSEEK ] - - -
%define SEEK_SET	0	
%define SEEK_CUR	1	
%define SEEK_END	2	
%define SEEK_DATA	3
%define SEEK_HOLE	4
%define SEEK_MAX	SEEK_HOLE

%define	RUSAGE_SELF	0
%define	RUSAGE_CHILDREN	-1
%define RUSAGE_BOTH	-2		
%define	RUSAGE_THREAD	1		

%define	PRIO_MIN	(-20)
%define	PRIO_MAX	20
%define ADDR_NO_RANDOMIZE 0x0040000
%define	PRIO_PROCESS	0
%define	PRIO_PGRP	1
%define	PRIO_USER	2
%define _STK_LIM	(8*1024*1024)
